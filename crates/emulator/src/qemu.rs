//! The QEMU differential harness: `qemu-riscv32`'s per-instruction register
//! log against the register trace the emulator's memory event log implies.
//!
//! The emulator side is replayed from the [`MemoryEventLog`] — the thing a
//! proof is about — rather than read off the machine, so what agrees with
//! QEMU here is the trace itself: every register value a proof would commit
//! to, instruction by instruction.
//!
//! # The invocation, frozen
//!
//! ```text
//! qemu-riscv32 -one-insn-per-tb -d nochain,cpu -D <log> <elf>  <input  3<hint
//! ```
//!
//! One instruction per translation block and no chaining between blocks, so
//! `-d cpu` logs the register file before every instruction. fd 0 and fd 3
//! are regular files, so a `read` returns everything asked for that the file
//! has, which is what the emulator's `read` returns. [`QEMU_FLAGS`] is the
//! flag list.
//!
//! # What may differ, and nothing else may
//!
//! 1. **The entry state.** Linux hands a new process a stack pointer, so
//!    QEMU's first record has `x2` set, where the emulator — whose VM has no
//!    loader — starts every register at 0. `x2` alone may differ there, and
//!    only until the guest first writes it, which crt0 does at its first
//!    instruction. This is not an instruction divergence and is not on the
//!    whitelist; it is the one fact about the two executors' environments
//!    that the comparison has to know.
//! 2. **[`WHITELIST`]**: `sc.w`, and only `sc.w`.
//!
//! Log formatting is normalized by reading only the ` pc` line and the
//! `xN/name value` pairs of each record.

use std::fmt;

use isa::{decode, Instr};
use loader::{ProgramImage, Slot};
use trace::{AddressSpace, MemoryEventLog};

/// The flags, frozen: one instruction per block, no chaining, CPU state.
pub const QEMU_FLAGS: [&str; 3] = ["-one-insn-per-tb", "-d", "nochain,cpu"];

/// A divergence the comparison accepts: the instruction, the rule that
/// bounds it, and why it is conformance rather than soundness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Divergence {
    pub instruction: &'static str,
    pub rule: &'static str,
    pub reason: &'static str,
}

/// The whitelist. One entry, and a test holds it to one.
pub const WHITELIST: [Divergence; 1] = [Divergence {
    instruction: "sc.w",
    rule: "in the record after an sc.w, rd may hold 1 in QEMU (the store-conditional \
           failed) where it holds 0 in the emulator (it always succeeds); that register \
           is then exempt until the emulator next writes it, and nothing else is exempt",
    reason: "the emulator's sc.w always succeeds, where the ISA makes an sc.w without a \
             valid reservation fail. That is conformance, not soundness: the verifier \
             still knows exactly which program ran, so 'this program produced this \
             output' holds unchanged. LLVM never emits an unpaired sc.w and never relies \
             on spurious failure, and the standard CAS loop exits on its first pass, so \
             compiled code cannot tell the two apart",
}];

/// One QEMU record: the pc and the register file before that instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub pc: u32,
    pub regs: [u32; 32],
}

/// One emulator instruction: the pc, the register file before it, the
/// instruction, and the registers it writes (bit `r` for `xr`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step {
    pub pc: u32,
    pub regs: [u32; 32],
    pub instr: Instr,
    pub writes: u32,
}

/// The comparison held: `records` instructions, `sc_w_whitelisted` of them
/// `sc.w`s whose failure under QEMU the whitelist accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Agreement {
    pub records: usize,
    pub sc_w_whitelisted: usize,
}

/// The first place the two traces differ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mismatch {
    /// The instruction's position in the run, from 0.
    pub index: usize,
    /// Its pc, as the emulator has it.
    pub pc: u32,
    /// The register that differs, if a register is what differs.
    pub reg: Option<usize>,
    pub reason: String,
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "QEMU and the emulator differ at instruction {} (pc {:#010x}): {}",
            self.index, self.pc, self.reason
        )
    }
}

/// Parse a `-d cpu` log: one record per ` pc` line, carrying the `xN/name
/// value` pairs that follow it. Every other token is formatting.
pub fn parse_log(text: &str) -> Result<Vec<Record>, String> {
    let mut out = Vec::new();
    let mut current: Option<(u32, [Option<u32>; 32])> = None;
    for (n, line) in text.lines().enumerate() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.first() == Some(&"pc") {
            if let Some(record) = current.take() {
                out.push(complete(record)?);
            }
            let pc = tokens
                .get(1)
                .and_then(|t| u32::from_str_radix(t, 16).ok())
                .ok_or_else(|| format!("line {}: a pc line with no hex pc", n + 1))?;
            current = Some((pc, [None; 32]));
            continue;
        }
        for pair in tokens.chunks(2) {
            let [name, value] = pair else { continue };
            let Some(index) = name
                .strip_prefix('x')
                .and_then(|rest| rest.split_once('/'))
                .and_then(|(i, _)| i.parse::<usize>().ok())
            else {
                continue;
            };
            let Some((_, regs)) = current.as_mut() else {
                return Err(format!("line {}: registers before any pc line", n + 1));
            };
            let slot = regs
                .get_mut(index)
                .ok_or_else(|| format!("line {}: there is no x{index}", n + 1))?;
            *slot = Some(
                u32::from_str_radix(value, 16)
                    .map_err(|_| format!("line {}: x{index} = {value} is not hex", n + 1))?,
            );
        }
    }
    if let Some(record) = current {
        out.push(complete(record)?);
    }
    Ok(out)
}

fn complete((pc, regs): (u32, [Option<u32>; 32])) -> Result<Record, String> {
    let mut out = [0u32; 32];
    for (r, value) in regs.iter().enumerate() {
        out[r] = value.ok_or_else(|| format!("the record at pc {pc:#010x} has no x{r}"))?;
    }
    Ok(Record { pc, regs: out })
}

/// The emulator's per-instruction register trace, replayed from its log.
///
/// A cycle is an instruction unless it is an ecall transfer — a cycle at an
/// `ecall` with no register query — which QEMU has no record of. The register
/// file before each instruction is the fold of every register write logged
/// before it, and every register read in the log is checked against that
/// fold, so a log that disagrees with itself panics here rather than
/// comparing.
pub fn emulator_steps(image: &ProgramImage, log: &MemoryEventLog) -> Vec<Step> {
    let events = log.events();
    let mut regs = [0u32; 32];
    let mut steps = Vec::new();
    let mut i = 0;
    while i < events.len() {
        let cycle = events[i].cycle();
        let end = i + events[i..]
            .iter()
            .take_while(|e| e.cycle() == cycle)
            .count();
        let events = &events[i..end];
        let first = events[0];
        assert!(
            first.space == AddressSpace::Pc && first.delta() == 0,
            "cycle {cycle} does not open with its pc query"
        );
        let pc = first.read_value;
        let instr = match image.slot_at(pc) {
            Some(Slot::Instruction { word, .. }) => decode(word).unwrap_or_else(|e| {
                panic!("the log ran pc {pc:#010x}, which does not decode: {e:?}")
            }),
            other => panic!("the log ran pc {pc:#010x}, which is {other:?}"),
        };
        let registers = || events.iter().filter(|e| e.space == AddressSpace::Reg);
        if !(instr == Instr::Ecall && registers().count() == 0) {
            let writes = registers()
                .filter(|e| e.delta() == 3)
                .fold(0u32, |mask, e| mask | 1 << e.addr);
            steps.push(Step {
                pc,
                regs,
                instr,
                writes,
            });
        }
        for e in registers() {
            assert_eq!(
                e.read_value, regs[e.addr as usize],
                "the log reads x{} as {:#x} at ts {}, where its own writes left {:#x}",
                e.addr, e.read_value, e.ts, regs[e.addr as usize]
            );
            regs[e.addr as usize] = e.write_value;
        }
        i = end;
    }
    steps
}

/// Compare the emulator's trace with QEMU's, record by record, under the
/// entry-state rule and [`WHITELIST`] and nothing else.
pub fn compare(steps: &[Step], records: &[Record]) -> Result<Agreement, Mismatch> {
    let mut exempt = [false; 32];
    let mut sc_w_whitelisted = 0;
    let shared = steps.len().min(records.len());
    for index in 0..shared {
        let (step, record) = (&steps[index], &records[index]);
        let mismatch = |reg: Option<usize>, reason: String| Mismatch {
            index,
            pc: step.pc,
            reg,
            reason,
        };
        if index == 0 {
            for reg in 0..32 {
                if record.regs[reg] != step.regs[reg] {
                    if reg != 2 {
                        return Err(mismatch(
                            Some(reg),
                            format!(
                                "the entry states differ in x{reg} (emulator {:#010x}, QEMU \
                                 {:#010x}); only x2, Linux's initial stack pointer, may",
                                step.regs[reg], record.regs[reg]
                            ),
                        ));
                    }
                    exempt[2] = true;
                }
            }
        } else {
            let previous = &steps[index - 1];
            for (reg, e) in exempt.iter_mut().enumerate() {
                if previous.writes >> reg & 1 == 1 {
                    *e = false;
                }
            }
            if let Instr::ScW { rd, .. } = previous.instr {
                let rd = rd as usize;
                if rd != 0 && record.regs[rd] == 1 && step.regs[rd] == 0 {
                    exempt[rd] = true;
                    sc_w_whitelisted += 1;
                }
            }
        }
        if record.pc != step.pc {
            return Err(mismatch(None, format!("QEMU is at pc {:#010x}", record.pc)));
        }
        let differs = (0..32).find(|&r| !exempt[r] && record.regs[r] != step.regs[r]);
        if let Some(reg) = differs {
            return Err(mismatch(
                Some(reg),
                format!(
                    "x{reg} is {:#010x} in the emulator and {:#010x} in QEMU",
                    step.regs[reg], record.regs[reg]
                ),
            ));
        }
    }
    if steps.len() != records.len() {
        return Err(Mismatch {
            index: shared,
            pc: steps.get(shared).map_or(0, |s| s.pc),
            reg: None,
            reason: format!(
                "the emulator ran {} instructions and QEMU {}",
                steps.len(),
                records.len()
            ),
        });
    }
    Ok(Agreement {
        records: shared,
        sc_w_whitelisted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "\
 pc       00010000
 x0/zero  00000000 x1/ra    00000000 x2/sp    2b2abe10 x3/gp    00000000
 x4/tp    00000000 x5/t0    00000000 x6/t1    00000000 x7/t2    00000000
 x8/s0    00000000 x9/s1    00000000 x10/a0   00000000 x11/a1   00000000
 x12/a2   00000000 x13/a3   00000000 x14/a4   00000000 x15/a5   00000000
 x16/a6   00000000 x17/a7   00000000 x18/s2   00000000 x19/s3   00000000
 x20/s4   00000000 x21/s5   00000000 x22/s6   00000000 x23/s7   00000000
 x24/s8   00000000 x25/s9   00000000 x26/s10  00000000 x27/s11  00000000
 x28/t3   00000000 x29/t4   00000000 x30/t5   00000000 x31/t6   00000000
 pc       00010004
 x0/zero  00000000 x1/ra    00000000 x2/sp    10000000 x3/gp    00000000
 x4/tp    00000000 x5/t0    00000000 x6/t1    00000000 x7/t2    00000000
 x8/s0    00000000 x9/s1    00000000 x10/a0   00000000 x11/a1   00000000
 x12/a2   00000000 x13/a3   00000000 x14/a4   00000000 x15/a5   00000000
 x16/a6   00000000 x17/a7   00000000 x18/s2   00000000 x19/s3   00000000
 x20/s4   00000000 x21/s5   00000000 x22/s6   00000000 x23/s7   00000000
 x24/s8   00000000 x25/s9   00000000 x26/s10  00000000 x27/s11  00000000
 x28/t3   00000000 x29/t4   00000000 x30/t5   00000000 x31/t6   00000000
";

    /// The emulator's side of `LOG`: `auipc sp, 0xfff0` at 0x10000, then
    /// anything at 0x10004.
    fn steps() -> Vec<Step> {
        let mut after = [0u32; 32];
        after[2] = 0x1000_0000;
        vec![
            Step {
                pc: 0x1_0000,
                regs: [0; 32],
                instr: Instr::Auipc {
                    rd: 2,
                    imm: 0x0fff_0000,
                },
                writes: 1 << 2,
            },
            Step {
                pc: 0x1_0004,
                regs: after,
                instr: Instr::Addi {
                    rd: 2,
                    rs1: 2,
                    imm: 0,
                },
                writes: 1 << 2,
            },
        ]
    }

    #[test]
    fn a_real_log_parses_and_agrees_under_the_entry_rule() {
        let records = parse_log(LOG).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].regs[2], 0x2b2a_be10);
        assert_eq!(
            compare(&steps(), &records),
            Ok(Agreement {
                records: 2,
                sc_w_whitelisted: 0
            })
        );
    }

    /// Acceptance 2 in miniature: one register of one emulator step,
    /// perturbed, is reported at exactly that step and register.
    #[test]
    fn a_perturbed_register_is_reported_where_it_is() {
        let records = parse_log(LOG).unwrap();
        let mut steps = steps();
        steps[1].regs[10] ^= 1;
        let m = compare(&steps, &records).unwrap_err();
        assert_eq!((m.index, m.pc, m.reg), (1, 0x1_0004, Some(10)));
    }

    /// The entry rule is x2's and nobody else's.
    #[test]
    fn the_entry_rule_covers_x2_only() {
        let mut records = parse_log(LOG).unwrap();
        records[0].regs[5] = 1;
        let m = compare(&steps(), &records).unwrap_err();
        assert_eq!((m.index, m.reg), (0, Some(5)));
    }

    /// ... and only until x2 is written.
    #[test]
    fn the_entry_rule_ends_at_the_first_write() {
        let mut records = parse_log(LOG).unwrap();
        records[1].regs[2] = 0x2b2a_be10;
        let m = compare(&steps(), &records).unwrap_err();
        assert_eq!((m.index, m.reg), (1, Some(2)));
    }

    #[test]
    fn a_length_difference_is_a_mismatch() {
        let records = parse_log(LOG).unwrap();
        let m = compare(&steps()[..1], &records).unwrap_err();
        assert_eq!(m.index, 1);
    }

    /// The sc.w rule: rd = 1 in QEMU where the emulator has 0 is accepted in
    /// the record after an sc.w, and only there, and only in rd.
    #[test]
    fn the_whitelist_is_sc_w_and_bounded() {
        assert_eq!(WHITELIST.len(), 1);
        assert_eq!(WHITELIST[0].instruction, "sc.w");

        let sc = Instr::ScW {
            rd: 5,
            rs1: 10,
            rs2: 11,
            aq: false,
            rl: false,
        };
        let base = Step {
            pc: 0x1_0000,
            regs: [0; 32],
            instr: sc,
            writes: 1 << 5,
        };
        let after = Step {
            pc: 0x1_0004,
            regs: [0; 32],
            instr: Instr::Fence {
                fm: 0,
                pred: 0,
                succ: 0,
            },
            writes: 0,
        };
        let mut failed = [0u32; 32];
        failed[5] = 1;
        let records = [
            Record {
                pc: 0x1_0000,
                regs: [0; 32],
            },
            Record {
                pc: 0x1_0004,
                regs: failed,
            },
        ];
        assert_eq!(
            compare(&[base, after], &records).unwrap().sc_w_whitelisted,
            1
        );

        // The same difference after anything but an sc.w is a mismatch.
        let add = Step {
            instr: Instr::Add {
                rd: 5,
                rs1: 0,
                rs2: 0,
            },
            ..base
        };
        assert_eq!(compare(&[add, after], &records).unwrap_err().reg, Some(5));

        // And a difference in any other register after the sc.w is too.
        let mut other = failed;
        other[6] = 1;
        let records = [
            records[0],
            Record {
                pc: 0x1_0004,
                regs: other,
            },
        ];
        assert_eq!(compare(&[base, after], &records).unwrap_err().reg, Some(6));
    }

    /// ... and the exemption ends when the emulator next writes rd: a QEMU
    /// rd still holding the failed sc.w's 1 after that is a mismatch.
    #[test]
    fn the_sc_w_exemption_ends_at_the_next_write_of_rd() {
        let sc = Instr::ScW {
            rd: 5,
            rs1: 10,
            rs2: 11,
            aq: false,
            rl: false,
        };
        let li = Instr::Addi {
            rd: 5,
            rs1: 0,
            imm: 7,
        };
        let fence = Instr::Fence {
            fm: 0,
            pred: 0,
            succ: 0,
        };
        let mut seven = [0u32; 32];
        seven[5] = 7;
        let steps = [
            Step {
                pc: 0x1_0000,
                regs: [0; 32],
                instr: sc,
                writes: 1 << 5,
            },
            Step {
                pc: 0x1_0004,
                regs: [0; 32],
                instr: li,
                writes: 1 << 5,
            },
            Step {
                pc: 0x1_0008,
                regs: seven,
                instr: fence,
                writes: 0,
            },
        ];
        let mut failed = [0u32; 32];
        failed[5] = 1;
        let record = |pc: u32, regs: [u32; 32]| Record { pc, regs };
        let agreeing = [
            record(0x1_0000, [0; 32]),
            record(0x1_0004, failed),
            record(0x1_0008, seven),
        ];
        assert_eq!(compare(&steps, &agreeing).unwrap().sc_w_whitelisted, 1);
        let stale = [
            record(0x1_0000, [0; 32]),
            record(0x1_0004, failed),
            record(0x1_0008, failed),
        ];
        let m = compare(&steps, &stale).unwrap_err();
        assert_eq!((m.index, m.reg), (2, Some(5)));
    }
}
