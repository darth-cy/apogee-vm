//! The trace: the memory self-check (acceptances 3 and 4), the timestamp
//! convention (acceptance 5, must-be-exact 3 and 10), routing (acceptance 6),
//! and the family buffers against the log they were recorded beside.

mod common;

use std::collections::BTreeSet;

use common::{instr_at, traced, TRACED};
use constants::{ecall, family, guest_memory, memory};
use emulator::trace_run;
use isa::Instr;
use program::row_kind;
use trace::{AddressSpace, MemoryEvent, MemoryEventLog, Query, Role, Row, ROLES};

fn rows_by_cycle(t: &common::Traced) -> Vec<(u32, Row)> {
    let mut rows: Vec<(u32, Row)> = t
        .traces
        .families
        .iter()
        .flat_map(|trace| (0..trace.len()).map(move |i| (trace.family, trace.row(i))))
        .collect();
    rows.sort_by_key(|(_, row)| row.cycle);
    rows
}

/// Acceptance 3: the read and write multisets balance, with init and
/// teardown derived, for every traced guest.
#[test]
fn the_memory_argument_balances() {
    for name in TRACED {
        let t = traced(name);
        t.log
            .self_check(&t.image)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

/// ... heap traffic included: `heap` writes words of the heap-and-stack
/// reservation well above its first page — the bump allocator's blocks, not
/// crt0's zeroing of `.bss` — and the log that holds them balances.
#[test]
fn the_heap_traffic_is_in_the_balanced_log() {
    let t = traced("heap");
    let reservation = t
        .image
        .segments
        .iter()
        .find(|s| {
            s.vaddr as u64 + s.mem_len as u64
                == guest_memory::RAM_ORIGIN as u64 + guest_memory::RAM_LENGTH as u64
        })
        .expect("the heap-and-stack reservation reaches the top of RAM");
    let heap_words: BTreeSet<u32> = t
        .log
        .events()
        .iter()
        .filter(|e| e.space == AddressSpace::Ram && e.read_value != e.write_value)
        .map(|e| e.addr)
        .filter(|a| *a >= reservation.vaddr + 64 && *a < reservation.vaddr + (1 << 20))
        .collect();
    assert!(
        heap_words.len() > 100,
        "heap changed only {} heap words",
        heap_words.len()
    );
    t.log.self_check(&t.image).unwrap();
}

/// Acceptance 4: one corrupted event fails the self-check, naming the
/// address space, the address and the timestamp where the log stops
/// balancing — for a RAM read, a register write mid-chain, a pc write, and a
/// timestamp that no longer precedes its write.
#[test]
fn a_corrupted_event_is_named() {
    let t = traced("fib");
    let events = t.log.events();
    let check = |events: Vec<MemoryEvent>| MemoryEventLog::from_events(events).self_check(&t.image);
    assert_eq!(
        check(events.to_vec()),
        Ok(()),
        "the untouched log is the control"
    );
    let named = |events: Vec<MemoryEvent>| {
        let e = check(events).expect_err("a tampered log must fail");
        (e.space, e.addr, e.ts)
    };

    // A RAM word read back after the run wrote it: its read value changed.
    let i = events
        .iter()
        .position(|e| {
            e.space == AddressSpace::Ram && e.read_ts > 0 && e.read_value == e.write_value
        })
        .expect("fib reads back a word it wrote");
    let mut tampered = events.to_vec();
    tampered[i].read_value ^= 1;
    assert_eq!(
        named(tampered),
        (AddressSpace::Ram, events[i].addr, events[i].ts)
    );

    // A register written and then read: the write changed, the reader named.
    let (w, r) = events
        .iter()
        .enumerate()
        .filter(|(_, e)| e.space == AddressSpace::Reg && e.delta() == 3 && e.addr != 0)
        .find_map(|(w, e)| {
            events[w + 1..]
                .iter()
                .position(|x| x.space == AddressSpace::Reg && x.addr == e.addr)
                .map(|r| (w, w + 1 + r))
        })
        .expect("fib reads a register it wrote");
    let mut tampered = events.to_vec();
    tampered[w].write_value ^= 1;
    assert_eq!(
        named(tampered),
        (AddressSpace::Reg, events[r].addr, events[r].ts)
    );

    // Cycle 10's pc write: PC continuity is in the multiset, so cycle 11's
    // pc read is where it breaks.
    let p = events
        .iter()
        .position(|e| e.space == AddressSpace::Pc && e.cycle() == 10)
        .unwrap();
    let mut tampered = events.to_vec();
    tampered[p].write_value = tampered[p].write_value.wrapping_add(4);
    assert_eq!(
        named(tampered),
        (AddressSpace::Pc, 0, events[p].ts + memory::TS_STEP)
    );

    // A read that no longer strictly precedes its write: a negative gap.
    let mut tampered = events.to_vec();
    tampered[i].read_ts = tampered[i].ts;
    let e = check(tampered).unwrap_err();
    assert_eq!(
        (e.space, e.addr, e.ts),
        (AddressSpace::Ram, events[i].addr, events[i].ts)
    );
    assert!(e.reason.contains("gap"), "{e}");

    // An initial value that is not the image's: a RAM word's first read, and
    // the entry pc's. Init comes from the image, never from the log, so a
    // forged first read cannot balance.
    let i = events
        .iter()
        .position(|e| e.space == AddressSpace::Ram && e.read_ts == 0)
        .expect("fib touches RAM");
    let mut tampered = events.to_vec();
    tampered[i].read_value ^= 1;
    assert_eq!(
        named(tampered),
        (AddressSpace::Ram, events[i].addr, events[i].ts)
    );
    let mut tampered = events.to_vec();
    tampered[0].read_value += 2;
    assert_eq!(named(tampered), (AddressSpace::Pc, 0, events[0].ts));

    // A stale read: a register read that sees the write before the one it
    // should, with that write's value and a valid gap, and writes it back.
    // It must not be its register's last query: then teardown would read the
    // stale value back and the values alone would stop balancing. With a
    // later query, the values alone still balance, only the timestamps in the
    // balance catch it, and the replay names the stale read, not the honest
    // reader.
    let (r, prior) = events
        .iter()
        .enumerate()
        .find_map(|(r, e)| {
            if e.space != AddressSpace::Reg || e.delta() == 3 || e.read_ts == 0 {
                return None;
            }
            events[r + 1..]
                .iter()
                .find(|x| x.space == e.space && x.addr == e.addr)?;
            let writer = events
                .iter()
                .find(|w| w.space == e.space && w.addr == e.addr && w.ts == e.read_ts)?;
            (writer.read_ts > 0 && writer.read_value != e.read_value).then_some((r, *writer))
        })
        .expect("fib reads a register whose last write replaced an earlier value");
    let mut tampered = events.to_vec();
    tampered[r].read_ts = prior.read_ts;
    tampered[r].read_value = prior.read_value;
    tampered[r].write_value = prior.read_value;
    assert_eq!(
        named(tampered),
        (AddressSpace::Reg, events[r].addr, events[r].ts)
    );
}

/// Acceptance 5 and must-be-exact 3: every event of every traced guest on
/// the four-slot clock — cycles from 1 advancing by one, each opening with
/// its pc query at slot 0, slots non-decreasing inside a cycle, every gap
/// non-negative, and no two queries at one address sharing a slot.
#[test]
fn every_event_keeps_the_four_slot_clock() {
    for name in TRACED {
        let t = traced(name);
        let events = t.log.events();
        let mut cycle = 0u64;
        let mut addresses = BTreeSet::new();
        for (i, e) in events.iter().enumerate() {
            assert!(
                e.ts < 1 << memory::TS_BITS,
                "{name}: event {i} is off the clock"
            );
            assert!(e.delta() < memory::TS_STEP);
            assert!(
                e.read_ts < e.ts,
                "{name}: event {i} has a negative gap ({} after {})",
                e.read_ts,
                e.ts
            );
            if e.cycle() != cycle {
                assert_eq!(e.cycle(), cycle + 1, "{name}: event {i} skips a cycle");
                assert_eq!(
                    (e.space, e.delta()),
                    (AddressSpace::Pc, 0),
                    "{name}: cycle {} does not open with its pc query",
                    e.cycle()
                );
                cycle = e.cycle();
                addresses.clear();
            } else {
                assert_ne!(
                    e.space,
                    AddressSpace::Pc,
                    "{name}: a second pc query in cycle {cycle}"
                );
                assert!(
                    e.delta() >= events[i - 1].delta(),
                    "{name}: slots go backwards"
                );
            }
            // One address may be queried at two slots of a cycle — `addi sp,
            // sp, 0` reads x2 at slot 1 and writes it at slot 3 — but never
            // twice in one slot.
            assert!(
                addresses.insert((e.space, e.addr, e.delta())),
                "{name}: two queries at {:?} {:#x} share slot {} of cycle {cycle}",
                e.space,
                e.addr,
                e.delta()
            );
        }
        assert_eq!(
            cycle, t.execution.cycle_count,
            "{name}: the last cycle is the count"
        );
    }
}

/// Acceptance 5: an `amoadd.w` in `atomics`' loop fills all four slots of
/// its cycle, with the RAM read-modify-write and the `rd` write sharing slot 3.
#[test]
fn an_amoadd_w_occupies_all_four_slots() {
    let t = traced("atomics");
    let amoadd: Vec<u64> = rows_by_cycle(&t)
        .iter()
        .filter(|(_, row)| matches!(instr_at(&t.image, row.pc), Instr::AmoaddW { .. }))
        .map(|(_, row)| row.cycle)
        .collect();
    assert!(
        amoadd.len() >= 37,
        "atomics ran only {} amoadd.w",
        amoadd.len()
    );
    for cycle in amoadd {
        let events: Vec<&MemoryEvent> = t
            .log
            .events()
            .iter()
            .filter(|e| e.cycle() == cycle)
            .collect();
        let slots: BTreeSet<u64> = events.iter().map(|e| e.delta()).collect();
        assert_eq!(slots, BTreeSet::from([0, 1, 2, 3]), "cycle {cycle}");
        let slot3: Vec<AddressSpace> = events
            .iter()
            .filter(|e| e.delta() == 3)
            .map(|e| e.space)
            .collect();
        assert_eq!(
            slot3,
            [AddressSpace::Ram, AddressSpace::Reg],
            "cycle {cycle}"
        );
    }
}

/// Acceptance 6: fib's cycles each land in exactly one family, the one an
/// independent reading of the image assigns its pc, and the counts sum to the
/// cycle count.
#[test]
fn every_cycle_lands_in_the_family_of_its_pc() {
    let t = traced("fib");
    assert_eq!(t.profile.total(), t.execution.cycle_count);
    let mut seen = vec![false; t.execution.cycle_count as usize + 1];
    for (trace, (f, n)) in t.traces.families.iter().zip(&t.profile.counts) {
        assert_eq!((trace.family, trace.len() as u64), (*f, *n));
        for (pc, cycle) in trace.pc.iter().zip(&trace.cycle) {
            let (owner, _) = row_kind(&instr_at(&t.image, *pc));
            assert_eq!(owner, trace.family, "cycle {cycle} at pc {pc:#x}");
            assert!(!seen[*cycle as usize], "cycle {cycle} routed twice");
            seen[*cycle as usize] = true;
        }
    }
    assert!(seen[1..].iter().all(|s| *s), "a cycle was routed nowhere");
}

/// ... and `atomics` routes every A-extension cycle, and nothing else, to
/// the atomics buffer, which its derived `VmConfig` has.
#[test]
fn atomics_cycles_route_to_the_atomics_family() {
    let t = traced("atomics");
    assert!(t.config.height(family::ATOMICS).is_some());
    let mut atomic_rows = 0;
    for trace in &t.traces.families {
        for pc in &trace.pc {
            let is_atomic = instr_at(&t.image, *pc).aq_rl().is_some();
            assert_eq!(is_atomic, trace.family == family::ATOMICS, "pc {pc:#x}");
            atomic_rows += is_atomic as usize;
        }
    }
    assert_eq!(atomic_rows, t.traces.family(family::ATOMICS).unwrap().len());
    assert!(atomic_rows > 37 * 9, "only {atomic_rows} atomic cycles");
}

/// Must-be-exact 4: a pc no table claims is a loud internal error, never a
/// skip. fib with its jump/branch family taken out of both the tables and
/// the config reaches such a pc at its first jump.
#[test]
#[should_panic(expected = "claimed by no family")]
fn a_pc_no_family_claims_panics() {
    let fib = common::image("fib");
    let (mut tables, mut config) = common::preprocess(&fib);
    tables
        .families
        .retain(|t| t.family != family::JUMP_BRANCH_SLT);
    config
        .families
        .retain(|(f, _)| *f != family::JUMP_BRANCH_SLT);
    let _ = trace_run(&fib, &common::io(&common::fib_record().0), &tables, &config);
}

/// The frame convention, restated from `docs/spec/execution-trace.md` rather
/// than from the emulator: the roles a cycle of each instruction class has.
fn frame(instr: &Instr, row: &Row) -> u8 {
    use Instr::*;
    use Role::*;
    let roles = |roles: &[Role]| roles.iter().fold(0u8, |m, r| m | 1 << *r as u8);
    match instr {
        Lui { .. } | Auipc { .. } | Jal { .. } => roles(&[Rd]),
        Jalr { .. }
        | Addi { .. }
        | Slti { .. }
        | Sltiu { .. }
        | Xori { .. }
        | Ori { .. }
        | Andi { .. }
        | Slli { .. }
        | Srli { .. }
        | Srai { .. } => roles(&[Rs1, Rd]),
        Beq { .. } | Bne { .. } | Blt { .. } | Bge { .. } | Bltu { .. } | Bgeu { .. } => {
            roles(&[Rs1, Rs2])
        }
        Lb { .. } | Lh { .. } | Lw { .. } | Lbu { .. } | Lhu { .. } => roles(&[Rs1, Load, Rd]),
        Sb { .. } | Sh { .. } | Sw { .. } => roles(&[Rs1, Rs2, Ram]),
        Fence { .. } => 0,
        LrW { .. } => roles(&[Rs1, Ram, Rd]),
        ScW { .. }
        | AmoswapW { .. }
        | AmoaddW { .. }
        | AmoxorW { .. }
        | AmoandW { .. }
        | AmoorW { .. }
        | AmominW { .. }
        | AmomaxW { .. }
        | AmominuW { .. }
        | AmomaxuW { .. } => roles(&[Rs1, Rs2, Ram, Rd]),
        Ecall if row.next_pc == row.pc => roles(&[Ram]),
        Ecall => match row.queries[Rs1 as usize].read_value {
            ecall::READ | ecall::WRITE => roles(&[Rs1, Rs2, Arg1, Arg2, Rd]),
            ecall::EXIT | ecall::PRECOMPILE_POSEIDON2 => roles(&[Rs1, Rs2, Rd]),
            _ => roles(&[Rs1, Rd]),
        },
        Ebreak => panic!("an ebreak has no row"),
        _ => roles(&[Rs1, Rs2, Rd]),
    }
}

/// Must-be-exact 3 and 10, row by row: each cycle has exactly its class's
/// roles; each register role names the instruction's own register — or, on
/// an ecall row, `a7`, `a0`, `a1`, `a2` and `a0`; `rd = x0` logs a write-back
/// of 0; an absent role is all zero; and `next_pc` is the fall-through except
/// where control moved.
#[test]
fn every_row_carries_its_class_frame() {
    for name in TRACED {
        let t = traced(name);
        for (_, row) in rows_by_cycle(&t) {
            let instr = instr_at(&t.image, row.pc);
            let at = format!(
                "{name}: cycle {} at {:#x} ({})",
                row.cycle,
                row.pc,
                instr.mnemonic()
            );
            assert_eq!(row.present, frame(&instr, &row), "{at}");
            for role in ROLES {
                if row.query(role).is_none() {
                    assert_eq!(row.queries[role as usize], Query::ABSENT, "{at}: {role:?}");
                }
            }
            let reg = |role: Role| row.query(role).map(|q| q.addr);
            let f = instr.fields();
            if instr == Instr::Ecall {
                if row.next_pc != row.pc {
                    assert_eq!(reg(Role::Rs1), Some(17), "{at}");
                    assert_eq!(reg(Role::Rd), Some(10), "{at}");
                    for (role, r) in [(Role::Rs2, 10), (Role::Arg1, 11), (Role::Arg2, 12)] {
                        assert!(reg(role).is_none_or(|a| a == r), "{at}: {role:?}");
                    }
                    assert_eq!(row.next_pc, row.pc + 4, "{at}");
                }
            } else {
                assert_eq!(
                    reg(Role::Rs1),
                    f.rs1
                        .map(u32::from)
                        .filter(|_| row.query(Role::Rs1).is_some()),
                    "{at}"
                );
                assert_eq!(
                    reg(Role::Rs2),
                    f.rs2
                        .map(u32::from)
                        .filter(|_| row.query(Role::Rs2).is_some()),
                    "{at}"
                );
                assert_eq!(
                    reg(Role::Rd),
                    f.rd.map(u32::from)
                        .filter(|_| row.query(Role::Rd).is_some()),
                    "{at}"
                );
                if let Some(q) = row.query(Role::Rd) {
                    if q.addr == 0 {
                        assert_eq!((q.read_value, q.write_value), (0, 0), "{at}: x0");
                    }
                }
                let jumps = matches!(
                    instr,
                    Instr::Jal { .. }
                        | Instr::Jalr { .. }
                        | Instr::Beq { .. }
                        | Instr::Bne { .. }
                        | Instr::Blt { .. }
                        | Instr::Bge { .. }
                        | Instr::Bltu { .. }
                        | Instr::Bgeu { .. }
                );
                if !jumps {
                    let len = match t.image.slot_at(row.pc) {
                        Some(loader::Slot::Instruction {
                            compressed: true, ..
                        }) => 2,
                        _ => 4,
                    };
                    assert_eq!(row.next_pc, row.pc + len, "{at}");
                }
            }
            for role in [Role::Rs1, Role::Rs2, Role::Arg1, Role::Arg2, Role::Load] {
                if let Some(q) = row.query(role) {
                    assert_eq!(
                        q.read_value, q.write_value,
                        "{at}: a read writes back what it read"
                    );
                }
            }
        }
    }
}

/// Must-be-exact 3's ecall transfers: a `read` or `write` that moved `n`
/// bytes is preceded by one transfer cycle per word those bytes touch, in
/// address order, each at the ecall's pc, re-writing that pc, and holding one
/// slot-3 RAM query; and every transfer cycle belongs to such an ecall. The
/// words' values too: a `read`'s transfer writes the stream's next bytes into
/// the buffer and leaves the word's other bytes as they were, a `write`'s
/// reads the stream's bytes out and writes the word back unchanged — and the
/// recorded fd 0, fd 1 and fd 2 streams are exactly the bytes the transfers
/// moved.
#[test]
fn an_ecall_s_transfers_precede_it_one_word_each() {
    let mut calls = 0;
    for name in TRACED {
        let t = traced(name);
        let rows = rows_by_cycle(&t);
        let io = &t.execution.io;
        let streams: [&[u8]; 4] = [&io.input, &io.output, &t.execution.stderr, &[]];
        let mut moved_so_far = [0usize; 4];
        let mut claimed = 0;
        for (i, (_, row)) in rows.iter().enumerate() {
            if instr_at(&t.image, row.pc) != Instr::Ecall || row.next_pc == row.pc {
                continue;
            }
            let number = row.queries[Role::Rs1 as usize].read_value;
            let moved = row.queries[Role::Rd as usize].write_value as i32;
            if !(number == 63 || number == 64) || moved <= 0 {
                continue;
            }
            let fd = row.queries[Role::Rs2 as usize].read_value as usize;
            let buf = row.queries[Role::Arg1 as usize].read_value;
            let (start, end) = (buf as u64, buf as u64 + moved as u64);
            let first = buf & !3;
            let words = ((buf + moved as u32 - 1) & !3) - first;
            let words = (words / 4 + 1) as usize;
            for k in 0..words {
                let (_, transfer) = &rows[i - words + k];
                assert_eq!((transfer.pc, transfer.next_pc), (row.pc, row.pc), "{name}");
                assert_eq!(transfer.present, 1 << Role::Ram as u8, "{name}");
                let q = transfer.queries[Role::Ram as usize];
                assert_eq!(q.addr, first + 4 * k as u32, "{name}");
                assert_eq!(transfer.cycle + (words - k) as u64, row.cycle, "{name}");
                let (old, new) = (q.read_value.to_le_bytes(), q.write_value.to_le_bytes());
                for (b, (old, new)) in old.iter().zip(&new).enumerate() {
                    let addr = q.addr as u64 + b as u64;
                    if addr < start || addr >= end {
                        assert_eq!(new, old, "{name}: a byte beside the buffer changed");
                        continue;
                    }
                    let byte = streams[fd][moved_so_far[fd] + (addr - start) as usize];
                    if number == ecall::READ {
                        assert_eq!(*new, byte, "{name}: read delivered the wrong byte");
                    } else {
                        assert_eq!(
                            (*old, *new),
                            (byte, byte),
                            "{name}: write moved the wrong byte"
                        );
                    }
                }
            }
            moved_so_far[fd] += moved as usize;
            claimed += words;
            calls += 1;
        }
        assert_eq!(
            moved_so_far,
            [io.input.len(), io.output.len(), t.execution.stderr.len(), 0],
            "{name}: the recorded streams are the bytes the transfers moved"
        );
        let transfers = rows
            .iter()
            .filter(|(_, r)| r.pc == r.next_pc && instr_at(&t.image, r.pc) == Instr::Ecall)
            .count();
        assert_eq!(
            transfers, claimed,
            "{name}: a transfer cycle belongs to no ecall"
        );
    }
    assert!(calls >= 10, "only {calls} ecalls moved bytes");
}

/// The buffers carry everything the log does: rebuilt from the rows alone,
/// in cycle order, the log comes back event for event — the pc query's read
/// timestamp included, which a row does not store because it is always the
/// previous cycle's.
#[test]
fn the_rows_rebuild_the_log_exactly() {
    // Each role's slot, restated from `docs/spec/execution-trace.md` §7
    // rather than read from `Role::delta`, which is what is under test.
    const SLOT: [u64; 7] = [1, 2, 2, 2, 2, 3, 3];
    for role in ROLES {
        assert_eq!(role.delta(), SLOT[role as usize], "{role:?}");
    }
    assert!(
        ROLES
            .windows(2)
            .all(|w| SLOT[w[0] as usize] <= SLOT[w[1] as usize]),
        "a cycle's queries are logged by slot, and ROLES is that order"
    );
    for name in TRACED {
        let t = traced(name);
        let mut events = Vec::new();
        for (_, row) in rows_by_cycle(&t) {
            let base = memory::TS_STEP * row.cycle;
            events.push(MemoryEvent {
                space: AddressSpace::Pc,
                addr: 0,
                ts: base,
                read_ts: base - memory::TS_STEP,
                read_value: row.pc,
                write_value: row.next_pc,
            });
            for role in ROLES {
                if let Some(q) = row.query(role) {
                    events.push(MemoryEvent {
                        space: role.space(),
                        addr: q.addr,
                        ts: base + SLOT[role as usize],
                        read_ts: q.read_ts,
                        read_value: q.read_value,
                        write_value: q.write_value,
                    });
                }
            }
        }
        assert_eq!(events, t.log.events(), "{name}");
    }
}

/// `touched_addresses` and `final_state` are the last write of every address
/// the log names, sorted, and the final registers are the execution's.
#[test]
fn the_final_state_is_the_last_write_of_every_address() {
    for name in TRACED {
        let t = traced(name);
        let finals = t.log.final_state();
        let touched = t.log.touched_addresses();
        assert_eq!(touched.len(), finals.len());
        assert!(
            touched.windows(2).all(|w| w[0] < w[1]),
            "{name}: sorted and distinct"
        );
        for f in &finals {
            let last = t
                .log
                .events()
                .iter()
                .rev()
                .find(|e| e.space == f.space && e.addr == f.addr)
                .unwrap();
            assert_eq!((f.ts, f.value), (last.ts, last.write_value), "{name}");
            if f.space == AddressSpace::Reg {
                assert_eq!(
                    f.value, t.execution.regs[f.addr as usize],
                    "{name}: x{}",
                    f.addr
                );
            }
        }
        let pc = finals.last().unwrap();
        assert_eq!(pc.space, AddressSpace::Pc);
        assert_eq!(pc.ts, memory::TS_STEP * t.execution.cycle_count);
    }
}

/// Must-be-exact 2, without QEMU: every ecall row answers as
/// `docs/spec/ecall-abi.md` says. Each is `(a7, a0 read, a2 read, a0
/// written)`, zero where the call reads no such register. `opcodes`'
/// `cover_ecall` makes one call of each kind at its edge, in this order; every
/// guest ends in `exit(0)`; and every call anywhere is a `read`, a `write`, an
/// `exit`, or answered `-ENOSYS`.
#[test]
fn every_ecall_answers_as_the_abi_says() {
    let neg = |errno: u32| errno.wrapping_neg();
    for name in TRACED {
        let t = traced(name);
        let calls: Vec<(u32, u32, u32, u32)> = rows_by_cycle(&t)
            .iter()
            .filter(|(_, r)| instr_at(&t.image, r.pc) == Instr::Ecall && r.next_pc != r.pc)
            .map(|(_, r)| {
                let q = |role: Role| r.queries[role as usize];
                (
                    q(Role::Rs1).read_value,
                    q(Role::Rs2).read_value,
                    q(Role::Arg2).read_value,
                    q(Role::Rd).write_value,
                )
            })
            .collect();
        assert_eq!(calls.last(), Some(&(ecall::EXIT, 0, 0, 0)), "{name}");
        for &(number, fd, count, result) in &calls {
            match number {
                ecall::READ => assert!(
                    result <= count || (fd != 0 && fd != 3 && result == neg(ecall::EBADF)),
                    "{name}: read({fd}, _, {count}) = {result:#x}"
                ),
                ecall::WRITE => assert!(
                    result == count || (fd != 1 && fd != 2 && result == neg(ecall::EBADF)),
                    "{name}: write({fd}, _, {count}) = {result:#x}"
                ),
                ecall::EXIT => assert_eq!(result, fd, "{name}: exit writes back its status"),
                _ => assert_eq!(result, neg(ecall::ENOSYS), "{name}: ecall {number:#x}"),
            }
        }
        if name == "opcodes" {
            let (read, write) = (ecall::READ, ecall::WRITE);
            let edges = [
                (read, 0, 6, 6),
                (write, 1, 6, 6),
                (write, 1, 0, 0),
                (read, 1000, 4, neg(ecall::EBADF)),
                (write, 1000, 4, neg(ecall::EBADF)),
                (read, 3, 4, 0),
                (ecall::PRECOMPILE_POSEIDON2, 0, 0, neg(ecall::ENOSYS)),
                (ecall::ZKVM_IO_LAST, 0, 0, neg(ecall::ENOSYS)),
            ];
            // The precompile's a0 is its state pointer, wherever the stack is.
            let calls: Vec<_> = calls
                .iter()
                .map(|&(n, a0, count, result)| {
                    let a0 = if n == ecall::PRECOMPILE_POSEIDON2 {
                        0
                    } else {
                        a0
                    };
                    (n, a0, count, result)
                })
                .collect();
            assert!(
                calls.windows(edges.len()).any(|w| w == edges),
                "opcodes' cover_ecall calls are not {edges:?}: {calls:?}"
            );
        }
    }
}
