//! The trace: the memory self-check (acceptances 3 and 4), the timestamp
//! convention (acceptance 5, must-be-exact 3 and 10), routing (acceptance 6),
//! and the family buffers against the log they were recorded beside.

mod common;

use std::collections::BTreeSet;

use common::{instr_at, traced, TRACED};
use constants::{delegation, ecall, family, guest_memory, memory};
use emulator::trace_run;
use isa::Instr;
use program::row_kind;
use trace::{init_windows, AddressSpace, MemoryEvent, MemoryEventLog, Query, Role, Row, ROLES};

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
        Ecall => match row.queries[Rs1 as usize].read_value {
            // S25: a `read` carries the word it delivers, on this row, at
            // slot 3 beside the `a0` write — a different address, which
            // `docs/spec/execution-trace.md` §3 permits. A `write` carries no
            // RAM query at all, and there are no transfer cycles any more.
            // A `read` on a descriptor the ABI does not give it answers
            // `-EBADF` and moves nothing, so it has no `ram` query either.
            ecall::READ if row.query(Ram).is_some() => roles(&[Rs1, Rs2, Arg1, Arg2, Ram, Rd]),
            ecall::READ | ecall::WRITE => roles(&[Rs1, Rs2, Arg1, Arg2, Rd]),
            ecall::EXIT => roles(&[Rs1, Rs2, Rd]),
            // A delegation call reads its frame base from `a0` and carries the
            // mirror query besides, at slot 3 in the delegation family's own
            // address space (`docs/spec/delegation.md` §5.1). Asked of the
            // registry rather than of a number spelled here, because the
            // registry is where a delegation's number lives.
            //
            // Since S25 the guests traced here *do* make one: every guest that
            // touches fd 0 or fd 1 computes `io_digest` at exit, which routes
            // Poseidon2 and `Fr`'s arithmetic through their delegations. The
            // arm used to group `PRECOMPILE_POSEIDON2` with `EXIT`, which was
            // only ever right because nothing here reached it.
            n if program::delegation_family(n).is_some() => roles(&[Rs1, Rs2, Rd, Delegate]),
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
/// where control moved, and on the exit row, which writes `HALT_PC`.
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
                    let next_pc = if row.queries[Role::Rs1 as usize].read_value == ecall::EXIT {
                        memory::HALT_PC
                    } else {
                        row.pc + 4
                    };
                    assert_eq!(row.next_pc, next_pc, "{at}");
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

/// `docs/spec/memory.md` §5, the halting sentinel: every traced guest's pc
/// ends at `HALT_PC`, which exactly one event writes — the last pc write, the
/// exit row's — and no other pc query writes an odd value.
#[test]
fn the_exit_row_alone_writes_the_halting_sentinel() {
    for name in TRACED {
        let t = traced(name);
        let final_pc = t.log.final_state().pop().expect("a run has a final state");
        assert_eq!(
            (final_pc.space, final_pc.value),
            (AddressSpace::Pc, memory::HALT_PC),
            "{name}"
        );
        let pc_writes: Vec<&MemoryEvent> = t
            .log
            .events()
            .iter()
            .filter(|e| e.space == AddressSpace::Pc)
            .collect();
        let (last, rest) = pc_writes.split_last().expect("a run has cycles");
        assert_eq!(last.write_value, memory::HALT_PC, "{name}");
        for e in rest {
            assert_eq!(
                e.write_value % 2,
                0,
                "{name}: the pc query at ts {} writes {:#x}",
                e.ts,
                e.write_value
            );
        }
        let (_, exit_row) = rows_by_cycle(&t).pop().expect("a run has rows");
        assert_eq!(instr_at(&t.image, exit_row.pc), Instr::Ecall, "{name}");
        assert_eq!(
            (
                exit_row.queries[Role::Rs1 as usize].read_value,
                exit_row.next_pc
            ),
            (ecall::EXIT, memory::HALT_PC),
            "{name}: the last row is the exit row"
        );
    }
}

/// A `read` carries the word it delivers, on its own row, and a `write`
/// carries no memory event at all (`docs/spec/execution-trace.md` §6).
///
/// S25 deleted the transfer cycle. Until then a `read` or a `write` that moved
/// `n` bytes was preceded by one cycle per word those bytes touched, and this
/// test walked them; now a provable `read` moves exactly one 4-aligned word
/// and its RAM query sits at slot 3 of the ecall's own row, beside the `a0`
/// write. What is checked here is the same three things, in the new shape:
///
/// * the word's address is the `a1` this row read, and its count is one word;
/// * the delivered bytes are the stream's next ones and **every other byte of
///   the word is left as it was** — the end-of-stream case, where fewer than
///   four arrive, is the one that makes that a real assertion;
/// * the recorded fd 0, fd 1 and fd 2 streams are exactly the bytes the ecalls
///   moved, and no other row makes a RAM query at an ecall's pc.
#[test]
fn a_read_carries_its_word_and_a_write_carries_none() {
    let mut reads = 0;
    let mut writes = 0;
    for name in TRACED {
        let t = traced(name);
        let rows = rows_by_cycle(&t);
        let io = &t.execution.io;
        let streams: [&[u8]; 4] = [&io.input, &io.output, &t.execution.stderr, &[]];
        let mut moved_so_far = [0usize; 4];
        for (_, row) in rows.iter() {
            if instr_at(&t.image, row.pc) != Instr::Ecall {
                continue;
            }
            let number = row.queries[Role::Rs1 as usize].read_value;
            if number != ecall::READ && number != ecall::WRITE {
                continue;
            }
            let moved = row.queries[Role::Rd as usize].write_value as i32;
            let fd = row.queries[Role::Rs2 as usize].read_value as usize;
            if number == ecall::WRITE {
                assert!(
                    row.query(Role::Ram).is_none(),
                    "{name}: a write carries a RAM query"
                );
                if moved > 0 {
                    moved_so_far[fd] += moved as usize;
                    writes += 1;
                }
                continue;
            }

            // A `read` that answered `-EBADF` moved nothing and made no
            // query. One that reached the **end of its stream** answered 0 and
            // made the query anyway, writing the word back unchanged — which
            // is what lets the circuit key the query's mask on "this row is a
            // `read`" with no "did it move anything" selector to constrain
            // (`docs/spec/execution-trace.md` §6).
            if moved < 0 {
                assert!(
                    row.query(Role::Ram).is_none(),
                    "{name}: a refused read carries a RAM query"
                );
                continue;
            }
            let buf = row.queries[Role::Arg1 as usize].read_value;
            assert_eq!(
                row.queries[Role::Arg2 as usize].read_value,
                ecall::READ_WORD_BYTES,
                "{name}: a provable read asks for exactly one word"
            );
            let q = row
                .query(Role::Ram)
                .unwrap_or_else(|| panic!("{name}: a read that moved bytes has no RAM query"));
            assert_eq!(q.addr, buf, "{name}: the word is not the buffer");
            assert_eq!(q.addr % 4, 0, "{name}: the buffer is not word-aligned");
            assert!(
                moved as u32 <= ecall::READ_WORD_BYTES,
                "{name}: a read delivered more than one word"
            );

            let (old, new) = (q.read_value.to_le_bytes(), q.write_value.to_le_bytes());
            if moved == 0 {
                assert_eq!(new, old, "{name}: an end-of-stream read changed the word");
                continue;
            }
            for (b, (old, new)) in old.iter().zip(&new).enumerate() {
                if b >= moved as usize {
                    assert_eq!(new, old, "{name}: a byte past the delivered ones changed");
                    continue;
                }
                assert_eq!(
                    *new,
                    streams[fd][moved_so_far[fd] + b],
                    "{name}: read delivered the wrong byte"
                );
            }
            moved_so_far[fd] += moved as usize;
            reads += 1;
        }
        assert_eq!(
            moved_so_far,
            [io.input.len(), io.output.len(), t.execution.stderr.len(), 0],
            "{name}: the recorded streams are the bytes the ecalls moved"
        );
        assert!(
            rows.iter()
                .all(|(_, r)| r.pc != r.next_pc || instr_at(&t.image, r.pc) != Instr::Ecall),
            "{name}: a cycle re-writes its own pc, which no row does since S25"
        );
    }
    assert!(reads >= 5, "only {reads} reads moved bytes");
    assert!(writes >= 10, "only {writes} writes moved bytes");
}

/// The buffers carry everything the log does: rebuilt from the rows alone,
/// in cycle order, the log comes back event for event — the pc query's read
/// timestamp included, which a row does not store because it is always the
/// previous cycle's. Every guest here that moves committed bytes delegates at
/// exit, so an invocation's frame words are filtered out rather than rebuilt:
/// they ride the requesting cycle and live in a `DelegationTrace`, never in a
/// `Row` (`docs/spec/delegation.md` §4.1).
#[test]
fn the_rows_rebuild_the_log_exactly() {
    // Each role's slot, restated from `docs/spec/execution-trace.md` §7 — and,
    // for the eighth, from `docs/spec/delegation.md` §5.1, the delegation
    // request's mirror query — rather than read from `Role::delta`, which is
    // what is under test.
    const SLOT: [u64; 8] = [1, 2, 2, 2, 2, 3, 3, 3];
    assert_eq!(
        SLOT[Role::Delegate as usize],
        delegation::ANCHOR_DELTA,
        "the mirror query sits at the slot the invocation's answer is stamped at"
    );
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
        // The cycles that made a delegation request, and which family: the
        // mirror query's address space is the row's, not the role's.
        let requested: std::collections::HashMap<u64, AddressSpace> = t
            .traces
            .delegations
            .iter()
            .flat_map(|d| {
                let space = program::delegation_space(d.family)
                    .and_then(AddressSpace::from_tag)
                    .expect("a delegation family has an anchor space");
                d.cycle.iter().map(move |c| (*c, space))
            })
            .collect();
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
                        space: role.space(requested.get(&row.cycle).copied()),
                        addr: q.addr,
                        ts: base + SLOT[role as usize],
                        read_ts: q.read_ts,
                        read_value: q.read_value,
                        write_value: q.write_value,
                    });
                }
            }
        }
        // A delegation **invocation's** frame accesses are not roles and are
        // not any row's: they ride the requesting cycle at
        // `delegation::FRAME_DELTA`, which is 0, so `(RAM, 0)` is a pair no
        // role has and is exactly how `trace`'s frame builder tells them apart
        // (`docs/spec/execution-trace.md` §7). Filtered out here rather than
        // rebuilt, because what this test is about is that the *rows* carry
        // the whole of their own contribution.
        //
        // Before S25 no guest traced here delegated and this filter removed
        // nothing. It does now: every guest that touches fd 0 or fd 1 computes
        // `io_digest` at exit. The count is asserted so that a future event
        // going missing cannot hide behind it.
        let is_frame = |e: &&MemoryEvent| e.space == AddressSpace::Ram && e.delta() == 0;
        let frame_events = t.log.events().iter().filter(is_frame).count();
        let words: usize = t
            .traces
            .delegations
            .iter()
            .map(|d| d.cycle.len() * d.words.len())
            .sum();
        assert_eq!(
            frame_events, words,
            "{name}: the events at (RAM, slot 0) are not the invocations' frames"
        );
        let rest: Vec<MemoryEvent> = t
            .log
            .events()
            .iter()
            .filter(|e| !is_frame(e))
            .copied()
            .collect();
        assert_eq!(events, rest, "{name}");
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

/// `docs/spec/memory.md` §3.4: `ZERO_WINDOWS`' shard list is the RAM windows
/// above 0 the log touches. fib's stack sits just below `2^31`, in the last
/// window `2^29 / h - 1` at every height, and at each of these three all else
/// it touches is in window 0 — not at the menu's `2^8`, which S21 added for
/// the keccak delegation family and where a window is 1 KiB, small enough that
/// fib's own image reaches past window 0. The test below holds `init_windows`
/// to the whole menu at every guest.
#[test]
fn fib_touches_only_the_image_window_and_the_stack_window() {
    let t = traced("fib");
    assert_eq!(init_windows(&t.log, 1 << 22), [127]);
    assert_eq!(init_windows(&t.log, 1 << 20), [511]);
    assert_eq!(init_windows(&t.log, 1 << 16), [8191]);
}

/// Every RAM word every traced guest touches lies in window 0 or in a listed
/// window, and every listed window holds one, at every menu height — and the
/// list passes the verifier's window rules.
#[test]
fn the_window_list_is_exactly_the_touched_windows_above_zero() {
    for name in TRACED {
        let t = traced(name);
        for height in family::HEIGHT_MENU {
            let windows = init_windows(&t.log, height);
            let touched: BTreeSet<u32> = t
                .log
                .events()
                .iter()
                .filter(|e| e.space == AddressSpace::Ram)
                .map(|e| e.addr / (4 * height))
                .collect();
            for w in &touched {
                assert!(
                    *w == 0 || windows.contains(w),
                    "{name} at {height}: a touched word in window {w} is in no shard"
                );
            }
            for w in &windows {
                assert!(
                    touched.contains(w),
                    "{name} at {height}: window {w} is listed and untouched"
                );
            }

            let mut config = t.config.clone();
            for (f, h) in config.families.iter_mut() {
                if *f == family::INIT_TEARDOWN || *f == family::ZERO_WINDOWS {
                    *h = height;
                }
            }
            let counts: Vec<u32> = config
                .families
                .iter()
                .map(|(f, _)| match *f {
                    family::INIT_TEARDOWN => 1,
                    family::ZERO_WINDOWS => windows.len() as u32,
                    _ => 0,
                })
                .collect();
            program::check_memory_windows(&config, &counts, &windows)
                .unwrap_or_else(|e| panic!("{name} at {height}: {e}"));
        }
    }
}

/// Must-be-exact 2, without QEMU: every ecall row answers as
/// `docs/spec/ecall-abi.md` says. Each is `(a7, a0 read, a2 read, a0
/// written)`, zero where the call reads no such register. `opcodes`'
/// `cover_ecall` makes one call of each kind at its edge, in this order; every
/// guest ends in `exit(0)` — `addsub` in `exit(42)` and `control` in
/// `exit(16)`, their results; and every
/// call anywhere is a `read`, a `write`, an `exit`, a delegation answered 0
/// (`docs/spec/delegation.md` §2), or answered `-ENOSYS`.
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
        let status = common::exit_code_of(name) as u32;
        assert_eq!(
            calls.last(),
            Some(&(ecall::EXIT, status, 0, status)),
            "{name}"
        );
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
                // An executor that has the circuit answers a delegation 0; one
                // without it answers `-ENOSYS`, which is what sends the shim
                // down its software path. No guest here calls one.
                n if program::delegation_family(n).is_some() => {
                    assert_eq!(result, 0, "{name}: delegation {number:#x}")
                }
                _ => assert_eq!(result, neg(ecall::ENOSYS), "{name}: ecall {number:#x}"),
            }
        }
        if name == "opcodes" {
            let (read, write) = (ecall::READ, ecall::WRITE);
            let edges = [
                // Two word reads where there was one six-byte read until S25:
                // a provable `read` moves exactly one 4-aligned word, so the
                // six payload bytes arrive as 4 then 2, and the short second
                // one is the end-of-stream edge worth having.
                (read, 0, 4, 4),
                (read, 0, 4, 2),
                // A `write` is unrestricted, so its edges are unchanged: a
                // count that is neither a word nor a multiple of one, the same
                // from an unaligned base on fd 2, and a zero-byte call.
                (write, 1, 6, 6),
                (write, 2, 6, 6),
                (write, 1, 0, 0),
                (read, 1000, 4, neg(ecall::EBADF)),
                (write, 1000, 4, neg(ecall::EBADF)),
                (read, 3, 4, 0),
                // The top of the precompile range, which no family answers:
                // since S23 the low numbers are *delegations*, and calling one
                // a guest did not declare is fatal rather than `-ENOSYS`.
                (ecall::PRECOMPILE_LAST, 0, 0, neg(ecall::ENOSYS)),
                (ecall::ZKVM_IO_LAST, 0, 0, neg(ecall::ENOSYS)),
            ];
            // The unassigned precompile's a0 is a pointer, wherever the stack is.
            let calls: Vec<_> = calls
                .iter()
                .map(|&(n, a0, count, result)| {
                    let a0 = if n == ecall::PRECOMPILE_LAST { 0 } else { a0 };
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
