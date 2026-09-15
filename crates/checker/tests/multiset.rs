//! S14's acceptance items and the design's controls, over a real execution:
//! fib's committed ELF traced with every family at `h = 2^16` — its frame over
//! all 2,117 cycles at 2^12 rows, `INIT_TEARDOWN`'s window 0, `ZERO_WINDOWS`'
//! stack window 8191, and its boundary — each tampered as an adversarial prover
//! would, beside its honest twin. "Does not reconcile" means: the tampered base
//! forwarded honestly, its roots recomputed by `memory_roots`, and
//! `gkr::reconciles` false. Where a tamper breaks a gate, `gkr::self_check`
//! names it.
//!
//! Every test says which item it is and what would make it fail. Cited rather
//! than repeated: acceptance 1 is `tests/memory.rs`' honest statement; 6's
//! closed-form half is `crates/constraints/tests/memory.rs`'
//! `the_read_sets_are_pinned`, 9 is `a_tuple_fed_from_a_witness_column_is_refused`
//! there, and 11's exhaustive half `the_gap_encoding_is_strict_at_reduced_width`;
//! 12 is `a_dropped_gap_obligation_fails_the_build` in
//! `crates/constraints/src/memory.rs`; 7's window list against the touched words
//! is `crates/emulator/tests/trace.rs`'
//! `the_window_list_is_exactly_the_touched_windows_above_zero`; and C2's rules at
//! their unit boundaries are `crates/program/tests/config.rs`'
//! `the_window_rules_hold_at_their_boundaries`.

mod common;

use checker::{
    check_padding_identity, memory_roots, violated_lookups, violated_relations, WitnessRow,
};
use common::{
    cell, forwarded_shard, frame_shard, memory_challenges, prove_and_verify, reconciled, roots,
    shards, traced, window_shard, window_shards, with_cells, witness_row, Shard, Traced, GUESTS,
    HEIGHT,
};
use constants::challenge_slot::{
    MEM_ALPHA_ADDR, MEM_ALPHA_TS, MEM_ALPHA_VAL, MEM_GAMMA, MEM_WINDOW_CONSTANT,
};
use constants::memory::{HALT_PC, TS_STEP};
use constants::{address_space, family};
use constraints::memory::{
    check_memory, frame, frame_artifact, gap_hi, image_window_artifact, zero_window_artifact,
    CYCLE, FIELD_ADDR, FIELD_MASK, FIELD_READ_TS, FIELD_READ_VALUE, FIELD_WRITE_VALUE, FRAME_DELTA,
    FRAME_NAMES, FRAME_QUERIES, FRAME_SPACE, RD,
};
use constraints::{CircuitArtifact, Coeff, GateDef, PolyAddress, VirtualKind};
use field::Fr;
use gkr::{
    boundary_factors, reconciles, self_check, BaseLayer, BoundaryFinals, ExternalChallenges,
    SelfCheckError,
};
use loader::ProgramImage;
use poly::{MultilinearPoly, PolyBacking};
use program::{check_memory_windows, ProgramError};
use trace::{
    build_boundary_finals, init_windows, plan_shards, AddressSpace, MemoryEvent, MemoryEventLog,
};

/// Frame queries by name, `docs/spec/memory.md` §2.1.
const PC: usize = 0;
const RS1: usize = 1;
const LOAD: usize = 5;
const RAM: usize = 6;

/// fib's stack window at `h = 2^16`: `2^29 / h − 1`.
const STACK_WINDOW: u32 = 8191;

fn int(v: u64) -> Fr {
    Fr::from_u64(v)
}

/// fib's honest statement: its trace, slots 1–4, its three shards — the frame,
/// window 0 and the stack window, in that order — and its finals.
struct Fib {
    t: Traced,
    memory: ExternalChallenges,
    shards: Vec<Shard>,
    finals: BoundaryFinals,
}

fn fib() -> Fib {
    let t = traced("fib", 24);
    let memory = memory_challenges();
    let shards = shards(&t, &memory);
    let labels: Vec<&str> = shards.iter().map(|s| s.label.as_str()).collect();
    assert_eq!(labels, ["frame", "window 0", "window 8191"]);
    let finals = build_boundary_finals(&t.log);
    Fib {
        t,
        memory,
        shards,
        finals,
    }
}

/// `shards` with shard `i`'s `cells` written, every other shard as it is.
fn tampered(shards: &[Shard], i: usize, cells: &[(PolyAddress, usize, Fr)]) -> Vec<Shard> {
    let edit = |(j, s): (usize, &Shard)| match j == i {
        true => with_cells(s, cells),
        false => s.clone(),
    };
    shards.iter().enumerate().map(edit).collect()
}

/// What a statement breaks: the first gate `gkr::self_check` names, shard by
/// shard; every `(row, obligation)` `violated_lookups` names on the frame, the
/// first shard; and whether the roots reconcile with `finals`.
#[derive(Debug, PartialEq)]
struct Surface {
    gate: Result<(), SelfCheckError>,
    lookups: Vec<(usize, String)>,
    reconciles: bool,
}

fn honest() -> Surface {
    Surface {
        gate: Ok(()),
        lookups: Vec::new(),
        reconciles: true,
    }
}

fn surface(f: &Fib, shards: &[Shard], finals: &BoundaryFinals) -> Surface {
    let mut gate = Ok(());
    let (mut reads, mut writes, mut lookups) = (Vec::new(), Vec::new(), Vec::new());
    for (i, shard) in shards.iter().enumerate() {
        let a = &shard.artifact;
        let values = forwarded_shard(shard);
        if gate.is_ok() {
            gate = self_check(a, &values, &shard.challenges);
        }
        let (read, write) =
            memory_roots(a, &values).unwrap_or_else(|e| panic!("{}: {e}", shard.label));
        reads.push(read);
        writes.push(write);
        if i == 0 {
            for row in 0..1usize << a.trace_vars {
                let names = violated_lookups(a, &witness_row(a, &values, row));
                lookups.extend(names.into_iter().map(|name| (row, name)));
            }
        }
    }
    let factors = boundary_factors(&f.memory, f.t.image.entry, finals);
    Surface {
        gate,
        lookups,
        reconciles: reconciles(&reads, &writes, factors),
    }
}

/// `T(AS, ADDR, TS, VAL) = γ_M + AS + α_addr·ADDR + α_ts·TS + α_val·VAL`,
/// written out.
fn tuple(memory: &ExternalChallenges, space: u8, addr: u64, ts: u64, value: Fr) -> Fr {
    let c = |slot| memory.get(slot).expect("a drawn slot");
    c(MEM_GAMMA)
        + int(space as u64)
        + c(MEM_ALPHA_ADDR) * int(addr)
        + c(MEM_ALPHA_TS) * int(ts)
        + c(MEM_ALPHA_VAL) * value
}

/// The frame query `(row, q)` holding `e`, in a frame over cycles `1..=n`: its
/// cycle's row, and the live query of its space and slot at its address
/// reading its timestamp.
fn locate(shard: &Shard, e: &MemoryEvent) -> (usize, usize) {
    let row = (e.cycle() - 1) as usize;
    let holds = |q: usize| {
        FRAME_SPACE[q] == e.space.tag()
            && FRAME_DELTA[q] == e.delta()
            && cell(shard, frame(q, FIELD_MASK), row) == Fr::ONE
            && cell(shard, frame(q, FIELD_ADDR), row) == int(e.addr as u64)
            && cell(shard, frame(q, FIELD_READ_TS), row) == int(e.read_ts)
    };
    let q = (0..FRAME_QUERIES).find(|&q| holds(q));
    (row, q.unwrap_or_else(|| panic!("the frame holds {e:?}")))
}

/// The first live row of `q` in fib's frame.
fn first_live(f: &Fib, q: usize) -> usize {
    let live = |y: &usize| cell(&f.shards[0], frame(q, FIELD_MASK), *y) == Fr::ONE;
    (0..f.t.cycles.len()).find(live).expect("fib has the query")
}

/// The shard counts of `t`'s statement with `init` `INIT_TEARDOWN` and `zero`
/// `ZERO_WINDOWS` shards.
fn counts(t: &Traced, init: u32, zero: u32) -> Vec<u32> {
    let count = |(f, n): &(u32, u32)| match *f {
        family::INIT_TEARDOWN => init,
        family::ZERO_WINDOWS => zero,
        _ => *n,
    };
    let plan = plan_shards(&t.profile, &t.config);
    plan.shards.iter().map(count).collect()
}

/// `v`'s canonical integer, which fits a `u64`.
fn small(v: Fr) -> u64 {
    let b = v.to_bytes();
    assert!(b[8..].iter().all(|x| *x == 0), "{v:?} is past 64 bits");
    u64::from_le_bytes(b[..8].try_into().expect("8 bytes"))
}

/// A `Fr`-backed column.
fn column(values: Vec<Fr>) -> MultilinearPoly {
    MultilinearPoly::new(PolyBacking::Fr(values))
}

/// The row of window `w` holding the word at byte address `addr`.
fn window_row(addr: u32, w: u32) -> usize {
    ((addr as u64 - 4 * HEIGHT as u64 * w as u64) / 4) as usize
}

// ---------------------------------------------------------------------------
// Acceptance
// ---------------------------------------------------------------------------

/// S14 acceptance 2, one value. fib's first RAM store — its `ram` query — reads
/// the word it overwrites; that read value moved by one leaves every gate and
/// every obligation holding, since none reads a store's read value, and the
/// roots do not reconcile: the read tuple is no write's. The honest twin keeps
/// every gate and obligation and reconciles. A value tamper's failure surface
/// is reconciliation alone.
///
/// Fails if the frame's read leaf did not bind `read_value`.
#[test]
fn one_changed_value_does_not_reconcile() {
    let f = fib();
    assert_eq!(surface(&f, &f.shards, &f.finals), honest());
    let row = first_live(&f, RAM);
    let value = cell(&f.shards[0], frame(RAM, FIELD_READ_VALUE), row) + Fr::ONE;
    let forged = tampered(&f.shards, 0, &[(frame(RAM, FIELD_READ_VALUE), row, value)]);
    let expected = Surface {
        reconciles: false,
        ..honest()
    };
    assert_eq!(surface(&f, &forged, &f.finals), expected);
}

/// S14 acceptance 3, one timestamp, in both of its places on fib's row 10,
/// cycle 11:
///
/// - its pc query's read timestamp moved one earlier, 40 to 39, with `gap_hi`
///   rewritten for the new gap (it stays 0): no gate and no obligation breaks,
///   and the roots do not reconcile — acceptance 2's surface;
/// - its cycle moved one earlier, 11 to 10, which moves all eight of the row's
///   write timestamps four earlier: the roots do not reconcile, and the lookup
///   evaluator also names, on that row, the low chunk of every live query whose
///   gap was below 4 and went negative — measured: the pc query's, whose gap is
///   always 3, and `rs1`'s.
///
/// So the surfaces differ: a value enters no obligation, and a timestamp that
/// moves a gap below 0 is caught by the lookup evaluator as well as by
/// reconciliation. Fails if the read leaf did not bind `read_ts`, the write leaf
/// `cycle`, or the gap obligations `cycle`.
#[test]
fn one_changed_timestamp_does_not_reconcile_and_a_moved_cycle_breaks_a_gap() {
    let f = fib();
    const ROW: usize = 10;
    let read_ts = frame(PC, FIELD_READ_TS);
    assert_eq!(cell(&f.shards[0], read_ts, ROW), int(40));
    let gap = TS_STEP * 11 - 39 - 1;
    let cells = [(read_ts, ROW, int(39)), (gap_hi(PC), ROW, int(gap >> 19))];
    let expected = Surface {
        reconciles: false,
        ..honest()
    };
    assert_eq!(
        surface(&f, &tampered(&f.shards, 0, &cells), &f.finals),
        expected
    );

    assert_eq!(cell(&f.shards[0], CYCLE, ROW), int(11));
    let at = |q, field| small(cell(&f.shards[0], frame(q, field), ROW));
    let short: Vec<String> = (0..FRAME_QUERIES)
        .filter(|&q| at(q, FIELD_MASK) == 1)
        .filter(|&q| TS_STEP * 11 + FRAME_DELTA[q] - at(q, FIELD_READ_TS) - 1 < TS_STEP)
        .map(|q| format!("gap_lo_{}", FRAME_NAMES[q]))
        .collect();
    assert_eq!(short, ["gap_lo_pc", "gap_lo_rs1"]);
    let forged = tampered(&f.shards, 0, &[(CYCLE, ROW, int(10))]);
    let expected = Surface {
        gate: Ok(()),
        lookups: short.into_iter().map(|name| (ROW, name)).collect(),
        reconciles: false,
    };
    assert_eq!(surface(&f, &forged, &f.finals), expected);
}

/// S14 acceptance 4, the future-read attack. fib's first three queries of
/// `x0`, Q1 < Q2 < Q3, each an `rs1` read of 0 written back: Q1 reads the init
/// at 0, Q2 reads Q1's write and Q3 Q2's. Swapping Q1's and Q3's read
/// timestamps permutes the read multiset, so the multisets balance and the
/// roots reconcile — while Q1 now reads Q2's write, from its own future. No gate
/// reads a read timestamp, so `gkr::self_check` passes; the lookup evaluator
/// names exactly `gap_lo_rs1` on Q1's row, whose gap `4·cycle + Δ − read_ts − 1`
/// is negative, and no high chunk rescues it: every `gap_hi` tried, from 1 to
/// `−1`, names an obligation too.
///
/// The cryptographic discharge of this obligation is S15's gate: until the
/// LogUp argument lands, the native evaluator is the only check that catches
/// this attack. Fails if the obligation did not bound the gap below by 0.
#[test]
fn a_future_read_balances_and_only_its_gap_obligation_catches_it() {
    let f = fib();
    let x0: Vec<MemoryEvent> =
        f.t.log
            .events()
            .iter()
            .copied()
            .filter(|e| e.space == AddressSpace::Reg && e.addr == 0)
            .take(3)
            .collect();
    let (q1, q2, q3) = (x0[0], x0[1], x0[2]);
    assert_eq!((q1.read_ts, q2.read_ts, q3.read_ts), (0, q1.ts, q2.ts));
    assert!(x0.iter().all(|e| (e.read_value, e.write_value) == (0, 0)));
    assert!(q3.read_ts > q1.ts, "Q1 reads from its future");
    let (r1, k1) = locate(&f.shards[0], &q1);
    let (r3, k3) = locate(&f.shards[0], &q3);
    assert_eq!((k1, k3), (RS1, RS1));
    let cells = [
        (frame(k1, FIELD_READ_TS), r1, int(q3.read_ts)),
        (frame(k3, FIELD_READ_TS), r3, int(q1.read_ts)),
    ];
    let forged = tampered(&f.shards, 0, &cells);
    let expected = Surface {
        gate: Ok(()),
        lookups: vec![(r1, format!("gap_lo_{}", FRAME_NAMES[k1]))],
        reconciles: true,
    };
    assert_eq!(surface(&f, &forged, &f.finals), expected);

    let a = &forged[0].artifact;
    let honest_row = witness_row(a, &forwarded_shard(&forged[0]), r1);
    let hi = a.committed().iter().position(|c| *c == gap_hi(k1));
    let hi = hi.expect("a gap column");
    for value in [Fr::ONE, int((1 << 19) - 1), int(1 << 19), Fr::MINUS_ONE] {
        let mut w = WitnessRow {
            committed: honest_row.committed.clone(),
            row: r1,
            scratch: Vec::new(),
        };
        w.committed[hi] = value;
        assert_ne!(violated_lookups(a, &w), Vec::<String>::new(), "{value:?}");
    }
}

/// A copy of `image` with the file-backed byte at `addr` flipped.
fn flipped(image: &ProgramImage, addr: u32) -> ProgramImage {
    let mut image = image.clone();
    for segment in image.segments.iter_mut() {
        if addr >= segment.vaddr && addr - segment.vaddr < segment.bytes.len() as u32 {
            segment.bytes[(addr - segment.vaddr) as usize] ^= 1;
            return image;
        }
    }
    panic!("{addr:#x} is not a file-backed byte")
}

/// S14 acceptance 5, the program image. fib touches one word of window 0,
/// `0x12000`, a file-backed word first touched by a read — a slot-2 RAM query,
/// which writes back what it read. One of its bytes flipped in the
/// `ProgramImage`, and window 0's columns, `S[0]` and teardown, rebuilt from the
/// flipped image beside the honest trace: the roots do not reconcile, because
/// the init tuple no longer holds the value the read consumed. The same flip
/// in a word nothing touches, the entry instruction's first byte, reconciles:
/// that row's init and teardown are both the flipped image's word and cancel —
/// which is why the test flips a word the trace reads.
///
/// Fails if the image column did not reach the init leaf.
#[test]
fn a_flipped_image_byte_under_a_read_word_does_not_reconcile() {
    let f = fib();
    let in_window_0 =
        |e: &&MemoryEvent| e.space == AddressSpace::Ram && (e.addr as u64) < 4 * HEIGHT as u64;
    let touched: Vec<&MemoryEvent> = f.t.log.events().iter().filter(in_window_0).collect();
    let read = touched[0];
    assert_eq!(
        (read.addr, read.read_ts, read.delta()),
        (0x12000, 0, FRAME_DELTA[LOAD])
    );
    let mut statement = f.shards.clone();
    let image = flipped(&f.t.image, read.addr);
    assert_ne!(image.initial_word(read.addr), read.read_value);
    statement[1] = window_shard(&f.t.log, &image, 0, &f.memory);
    assert!(!reconciled(
        &statement,
        &f.memory,
        f.t.image.entry,
        &f.finals
    ));

    let untouched = f.t.image.entry;
    assert!(touched.iter().all(|e| e.addr != untouched));
    let image = flipped(&f.t.image, untouched);
    assert_ne!(
        image.initial_word(untouched),
        f.t.image.initial_word(untouched)
    );
    statement[1] = window_shard(&f.t.log, &image, 0, &f.memory);
    assert!(reconciled(
        &statement,
        &f.memory,
        f.t.image.entry,
        &f.finals
    ));
}

/// S14 acceptance 6, uninitialized memory. `ZERO_WINDOWS` has no init-value
/// term — its read set is `M[0], M[1], V[row]`, pinned by
/// `crates/constraints/tests/memory.rs`' `the_read_sets_are_pinned` — so the
/// closed-form path cannot claim a nonzero init. Hand-forged here: that
/// artifact with a third memory column `M[2] init_value` and `(α_val, M[2])`
/// added to its init leaf, a lawful circuit `validate` and `check_memory`
/// accept. With `M[2]` all zero it is the real window's polynomial and fib's
/// honest trace reconciles; with `M[2] = 7` on the row of the first stack word
/// fib touches, `0x7ffffffc`, it does not. fib reads no stack word before
/// writing it — each of its 29 is first touched by a store, asserted here — but
/// every query reads, and that store's read side consumes the init tuple
/// `(0, 0)`.
///
/// Fails if a nonzero init value could balance an honest first read.
#[test]
fn a_forged_nonzero_init_value_does_not_reconcile() {
    let f = fib();
    let mut forged = zero_window_artifact(HEIGHT.trailing_zeros());
    let row = PolyAddress::Virtual(VirtualKind::RowIndex);
    let init_value = PolyAddress::Memory(2);
    let mut terms = vec![(Coeff::Challenge(MEM_ALPHA_ADDR), row); 4];
    terms.push((Coeff::Challenge(MEM_ALPHA_VAL), init_value));
    let init = GateDef::Linear {
        terms,
        constant: Coeff::Challenge(MEM_WINDOW_CONSTANT),
    };
    let entry = &mut forged.layers[0].producing[1];
    entry.gate = init.clone();
    forged.relations[entry.relation as usize].gate = init;
    forged.memory.push("init_value".to_string());
    forged.padding.row.push(Fr::ZERO);
    assert_eq!(forged.validate(), Ok(()));
    assert_eq!(check_memory(&forged), Ok(()));

    let in_stack = |e: &&MemoryEvent| {
        e.space == AddressSpace::Ram && e.addr as u64 / (4 * HEIGHT as u64) == STACK_WINDOW as u64
    };
    let first =
        f.t.log
            .events()
            .iter()
            .find(in_stack)
            .expect("a stack word");
    assert_eq!(
        (first.addr, first.read_ts, first.read_value),
        (0x7fff_fffc, 0, 0)
    );
    let mut stack_words = std::collections::BTreeMap::new();
    for e in f.t.log.events().iter().filter(in_stack) {
        stack_words.entry(e.addr).or_insert(e.delta());
    }
    assert_eq!(stack_words.len(), 29);
    assert!(stack_words.values().all(|d| *d == FRAME_DELTA[RAM]));
    let stack = &f.shards[2];
    let window = |value: Fr| {
        let mut init = vec![Fr::ZERO; HEIGHT as usize];
        init[window_row(first.addr, STACK_WINDOW)] = value;
        let mut columns: Vec<(PolyAddress, MultilinearPoly)> = [0, 1]
            .map(|m| (PolyAddress::Memory(m), cell_column(stack, m)))
            .into();
        columns.push((init_value, column(init)));
        Shard {
            label: "forged window 8191".to_string(),
            artifact: forged.clone(),
            base: BaseLayer::new(columns),
            challenges: stack.challenges.clone(),
        }
    };
    for (value, balances) in [(Fr::ZERO, true), (int(7), false)] {
        let statement = vec![f.shards[0].clone(), f.shards[1].clone(), window(value)];
        assert_eq!(
            reconciled(&statement, &f.memory, f.t.image.entry, &f.finals),
            balances,
            "{value:?}"
        );
    }
}

/// `shard`'s column `M[m]`.
fn cell_column(shard: &Shard, m: u32) -> MultilinearPoly {
    let address = PolyAddress::Memory(m);
    shard.base.get(address).expect("a window column").clone()
}

/// S14 acceptance 7, coverage and uniqueness at the columns: over fib's and
/// heap's statement windows — 0, then every id of `init_windows` — the rows
/// whose `teardown_ts` is not 0, read as `(4h·w + 4y, teardown_ts,
/// teardown_value)` in window then row order, are exactly the log's final RAM
/// state in address order. So every touched word has one teardown row, in one
/// window, holding its last write, and no other row claims a write. Fails if a
/// builder filed a word under the wrong window or row, or twice.
#[test]
fn every_touched_ram_word_has_exactly_one_teardown_row() {
    for (name, input) in GUESTS {
        let t = traced(name, input);
        let memory = memory_challenges();
        let mut ids = vec![0];
        ids.extend(init_windows(&t.log, HEIGHT));
        let windows = window_shards(&t, &memory);
        let mut rows = Vec::new();
        for (w, shard) in ids.iter().zip(&windows) {
            for y in 0..HEIGHT as usize {
                let ts = cell(shard, PolyAddress::Memory(0), y);
                if ts != Fr::ZERO {
                    let addr = 4 * HEIGHT as u64 * *w as u64 + 4 * y as u64;
                    rows.push((addr, ts, cell(shard, PolyAddress::Memory(1), y)));
                }
            }
        }
        let finals: Vec<(u64, Fr, Fr)> = t
            .log
            .final_state()
            .into_iter()
            .filter(|v| v.space == AddressSpace::Ram)
            .map(|v| (v.addr as u64, int(v.ts), int(v.value as u64)))
            .collect();
        assert!(!finals.is_empty(), "{name}");
        assert_eq!(rows, finals, "{name}");
    }
}

/// S14 acceptance 7, uniqueness is load-bearing (`docs/spec/memory.md` §9, the
/// design review's attack). fib's first store to a stack word already holding a
/// nonzero value, at `0x7fffff70`, made stale: it reads the init `(0, 0)`
/// instead of the last write `(195, 0x12728)`. Against the honest statement no
/// gate or obligation breaks and the roots do not reconcile. With a second
/// `ZERO_WINDOWS` shard for window 8191 — every word of the window given an
/// init row twice — holding that last write as teardown on the word's row and
/// zeros elsewhere, the stale read consumes the second init, the orphaned write
/// the second teardown, every other row cancels, and the roots reconcile with
/// nothing broken. `check_memory_windows` refuses the list `[8191, 8191]`
/// (`window_rules_refuse_each_single_change_of_fibs_statement`), the one rule
/// that stops it.
///
/// Fails if the forgery did not balance, which would mean the duplicate window
/// was not a real attack and the rule not load-bearing.
#[test]
fn a_duplicated_window_lets_a_stale_read_balance() {
    let f = fib();
    let stale = f.t.log.events().iter().find(|e| {
        e.space == AddressSpace::Ram
            && e.delta() == FRAME_DELTA[RAM]
            && e.addr / (4 * HEIGHT) == STACK_WINDOW
            && e.read_ts > 0
            && e.read_value != 0
    });
    let stale = stale.expect("a store over a written stack word");
    assert_eq!(
        (stale.addr, stale.read_ts, stale.read_value),
        (0x7fff_ff70, 195, 0x12728)
    );
    let (row, q) = locate(&f.shards[0], stale);
    assert_eq!(q, RAM);
    let cells = [
        (frame(RAM, FIELD_READ_TS), row, Fr::ZERO),
        (frame(RAM, FIELD_READ_VALUE), row, Fr::ZERO),
    ];
    let mut statement = tampered(&f.shards, 0, &cells);
    let expected = Surface {
        reconciles: false,
        ..honest()
    };
    assert_eq!(surface(&f, &statement, &f.finals), expected);

    let y = window_row(stale.addr, STACK_WINDOW);
    let (mut ts, mut value) = (
        vec![Fr::ZERO; HEIGHT as usize],
        vec![Fr::ZERO; HEIGHT as usize],
    );
    ts[y] = int(stale.read_ts);
    value[y] = int(stale.read_value as u64);
    let stack = &f.shards[2];
    statement.push(Shard {
        label: "window 8191, twice".to_string(),
        artifact: stack.artifact.clone(),
        base: BaseLayer::new(vec![
            (PolyAddress::Memory(0), column(ts)),
            (PolyAddress::Memory(1), column(value)),
        ]),
        challenges: stack.challenges.clone(),
    });
    assert_eq!(surface(&f, &statement, &f.finals), honest());
}

/// S14 acceptance 8, the honest half: in fib's frame every live query at REG
/// address 0 — `rs1`, `rs2`, `arg1`, `arg2` or `rd` — reads 0 and writes 0, and
/// there are as many as the log has `x0` queries, 432. Fails if the builders or
/// the execution let `x0` hold anything but 0.
#[test]
fn every_read_of_x0_returns_0() {
    let f = fib();
    let frame_shard = &f.shards[0];
    let mut x0 = 0;
    for row in 0..f.t.cycles.len() {
        for q in (0..FRAME_QUERIES).filter(|q| FRAME_SPACE[*q] == address_space::REG) {
            let at = |field| cell(frame_shard, frame(q, field), row);
            if at(FIELD_MASK) == Fr::ONE && at(FIELD_ADDR) == Fr::ZERO {
                assert_eq!(at(FIELD_READ_VALUE), Fr::ZERO, "row {row}, query {q}");
                assert_eq!(at(FIELD_WRITE_VALUE), Fr::ZERO, "row {row}, query {q}");
                x0 += 1;
            }
        }
    }
    let log = f.t.log.events().iter();
    let expected = log.filter(|e| e.space == AddressSpace::Reg && e.addr == 0);
    assert_eq!(x0, expected.count());
    assert_eq!(x0, 432);
}

/// S14 acceptance 8, the forged half, `docs/spec/memory.md` §2.4's note. fib's
/// first two `rd` writes to `x0` with no `x0` query between them, R1 then R2.
/// R1's write value set to 5 and R2's read value to 5: R2 consumes the 5 and
/// writes 0, so `x0` still ends at the verifier's 0, the multisets balance and
/// the roots reconcile, with every obligation holding — `v_0 = 0` alone does not
/// stop it. The x0 gadget does: `gkr::self_check` names `rd_write_masked` on
/// R1's row, the one relation the witness-row evaluator reports there.
///
/// Fails if the gadget did not mask an `rd` write at address 0.
#[test]
fn a_write_of_5_to_x0_balances_and_rd_write_masked_refuses_it() {
    let f = fib();
    let x0: Vec<MemoryEvent> =
        f.t.log
            .events()
            .iter()
            .filter(|e| e.space == AddressSpace::Reg && e.addr == 0)
            .copied()
            .collect();
    let rd = |e: &MemoryEvent| e.delta() == FRAME_DELTA[RD];
    let pair = x0.windows(2).find(|p| rd(&p[0]) && rd(&p[1]));
    let pair = pair.expect("two rd writes to x0 in a row");
    let (r1, k1) = locate(&f.shards[0], &pair[0]);
    let (r2, k2) = locate(&f.shards[0], &pair[1]);
    assert_eq!((k1, k2), (RD, RD));
    let cells = [
        (frame(RD, FIELD_WRITE_VALUE), r1, int(5)),
        (frame(RD, FIELD_READ_VALUE), r2, int(5)),
    ];
    let forged = tampered(&f.shards, 0, &cells);
    let gate = SelfCheckError {
        layer: 0,
        row: r1,
        relation: "rd_write_masked".to_string(),
    };
    let expected = Surface {
        gate: Err(gate),
        lookups: Vec::new(),
        reconciles: true,
    };
    assert_eq!(surface(&f, &forged, &f.finals), expected);
    let (a, challenges) = (&forged[0].artifact, &forged[0].challenges);
    let w = witness_row(a, &forwarded_shard(&forged[0]), r1);
    assert_eq!(violated_relations(a, &w, challenges), ["rd_write_masked"]);
}

/// S14 acceptance 10, padding. fib's frame at the menu height 2^16 — 2,117 live
/// rows and 63,419 padding rows — keeps every gate, proves, verifies and
/// discharges its base claims. Every committed cell of every padding row is the
/// artifact's padding row, all zeros, `cycle` included (`docs/spec/memory.md`
/// §2.1). On every padding row each of the 16 leaves, and every row-wise product
/// above them, is exactly 1 in the forwarded values; so its roots are the 2^12
/// frame's, and they reconcile with fib's windows. `check_padding_identity`
/// holds the artifact to the same clause. Fails if any padding cell were not 0 —
/// a cycle filled on a padding row past the first, which no leaf sees on a
/// mask-0 row — or if a masked leaf were not 1: a padding row would move a root.
#[test]
fn the_frame_padded_to_2_16_proves_and_its_padding_rows_are_1() {
    let f = fib();
    let live = f.t.cycles.len();
    let tall = frame_shard(&f.t.log, &f.t.cycles, 1 << 16, &f.memory);
    let padding = &tall.artifact.padding.row;
    assert!(
        padding.iter().all(|v| *v == Fr::ZERO),
        "an all-zero padding row"
    );
    for (i, address) in tall.artifact.committed().into_iter().enumerate() {
        let column = tall.base.get(address).expect("a committed column");
        for y in live..1 << 16 {
            assert_eq!(column.get(y), padding[i], "{address}, row {y}");
        }
    }
    let values = forwarded_shard(&tall);
    assert_eq!(
        self_check(&tall.artifact, &values, &tall.challenges),
        Ok(())
    );
    for (k, layer) in values.layers[..4].iter().enumerate() {
        for (j, column) in layer.iter().enumerate() {
            for y in live..1 << 16 {
                assert_eq!(
                    column.get(y),
                    Fr::ONE,
                    "layer {}, column {j}, row {y}",
                    k + 1
                );
            }
        }
    }
    let short = forwarded_shard(&f.shards[0]);
    assert_eq!(
        memory_roots(&tall.artifact, &values),
        memory_roots(&f.shards[0].artifact, &short)
    );
    let mut statement = f.shards.clone();
    statement[0] = tall.clone();
    assert!(reconciled(
        &statement,
        &f.memory,
        f.t.image.entry,
        &f.finals
    ));
    assert_eq!(check_padding_identity(&tall.artifact), Ok(()));
    assert_eq!(prove_and_verify(&tall, &values), Ok(()));
}

/// S14 acceptance 11, the full-width boundary: the frame's own `rs1`
/// obligations through `violated_lookups`, on a row at cycle `2^36`, where
/// `gap = 4·2^36 + 1 − read_ts − 1 = 2^38 − read_ts`. Gaps 0 and `2^38 − 1` with
/// `gap_hi = gap >> 19` are accepted; gaps −1 and `2^38` are refused with every
/// `gap_hi` tried — 0, 1, `2^19 − 1`, `2^19` and `−1`. The exhaustive statement
/// over every high chunk is the reduced-width test
/// `crates/constraints/tests/memory.rs`' `the_gap_encoding_is_strict_at_reduced_width`.
/// Fails if the chunk bound were not `2^19`, or the low chunk not the gap less
/// `2^19·hi`.
#[test]
fn the_gap_obligations_accept_exactly_0_through_2_38_minus_1() {
    let a = frame_artifact(4);
    let layout = a.committed();
    let at = |address| layout.iter().position(|c| *c == address).expect("a column");
    let top = int(1 << 38);
    let row = |gap: Fr, hi: Fr| {
        let mut committed = vec![Fr::ZERO; layout.len()];
        committed[at(CYCLE)] = int(1 << 36);
        committed[at(frame(RS1, FIELD_MASK))] = Fr::ONE;
        committed[at(frame(RS1, FIELD_READ_TS))] = top - gap;
        committed[at(gap_hi(RS1))] = hi;
        WitnessRow {
            committed,
            row: 0,
            scratch: Vec::new(),
        }
    };
    for gap in [0, (1 << 38) - 1] {
        let w = row(int(gap), int(gap >> 19));
        assert_eq!(violated_lookups(&a, &w), Vec::<String>::new(), "gap {gap}");
    }
    let his = [
        Fr::ZERO,
        Fr::ONE,
        int((1 << 19) - 1),
        int(1 << 19),
        Fr::MINUS_ONE,
    ];
    for (label, gap) in [("-1", Fr::MINUS_ONE), ("2^38", top)] {
        for hi in his {
            let names = violated_lookups(&a, &row(gap, hi));
            assert_ne!(names, Vec::<String>::new(), "gap {label}, hi {hi:?}");
        }
    }
    let lo = ["gap_lo_rs1".to_string()];
    let hi = ["gap_hi_rs1".to_string()];
    assert_eq!(violated_lookups(&a, &row(Fr::MINUS_ONE, Fr::ZERO)), lo);
    assert_eq!(violated_lookups(&a, &row(top, int(1 << 19))), hi);
    assert_eq!(violated_lookups(&a, &row(top, int((1 << 19) - 1))), lo);
}

// ---------------------------------------------------------------------------
// Controls
// ---------------------------------------------------------------------------

/// Window 0's artifact with both leaves unmasked: each the bare tuple of §3.3,
/// `V[ram_live]` gone. A lawful circuit.
fn unmasked_image_window() -> CircuitArtifact {
    let mut a = image_window_artifact(HEIGHT.trailing_zeros());
    let row = PolyAddress::Virtual(VirtualKind::RowIndex);
    let mut teardown = vec![(Coeff::Challenge(MEM_ALPHA_ADDR), row); 4];
    let mut init = teardown.clone();
    teardown.push((Coeff::Challenge(MEM_ALPHA_TS), PolyAddress::Memory(0)));
    teardown.push((Coeff::Challenge(MEM_ALPHA_VAL), PolyAddress::Memory(1)));
    init.push((Coeff::Challenge(MEM_ALPHA_VAL), PolyAddress::Setup(0)));
    for (j, terms) in [teardown, init].into_iter().enumerate() {
        let gate = GateDef::Linear {
            terms,
            constant: Coeff::Challenge(MEM_WINDOW_CONSTANT),
        };
        let entry = &mut a.layers[0].producing[j];
        entry.gate = gate.clone();
        a.relations[entry.relation as usize].gate = gate;
    }
    a.virtuals.retain(|(kind, _)| *kind != VirtualKind::RamLive);
    assert_eq!(a.validate(), Ok(()));
    a
}

/// Control C1, the head mask. On fib's first row with no `ram` query, a forged
/// one at word `0x4` — below `RAM_ORIGIN`, window 0's row 1 — reading `(0, 0)`
/// and writing 7, with window 0's teardown row 1 set to that write: every gate
/// and obligation holds, and the roots do not reconcile, because `V[ram_live]`
/// makes row 1's leaves 1 and leaves no init tuple for the read to consume. The
/// same forgery against the unmasked window 0 reconciles; that variant with
/// fib's honest trace reconciles too, so the mask is the only difference.
///
/// Fails if `V[ram_live]` did not remove window 0's rows below `RAM_ORIGIN`.
#[test]
fn a_query_below_ram_origin_balances_only_without_the_head_mask() {
    let f = fib();
    let empty = |y: &usize| cell(&f.shards[0], frame(RAM, FIELD_MASK), *y) == Fr::ZERO;
    let row = (0..f.t.cycles.len())
        .find(empty)
        .expect("a row without a store");
    for address in [
        frame(RAM, FIELD_ADDR),
        frame(RAM, FIELD_READ_TS),
        frame(RAM, FIELD_READ_VALUE),
        gap_hi(RAM),
    ] {
        assert_eq!(cell(&f.shards[0], address, row), Fr::ZERO, "{address}");
    }
    let ts = TS_STEP * (row as u64 + 1) + FRAME_DELTA[RAM];
    let cells = [
        (frame(RAM, FIELD_MASK), row, Fr::ONE),
        (frame(RAM, FIELD_ADDR), row, int(4)),
        (frame(RAM, FIELD_WRITE_VALUE), row, int(7)),
    ];
    let mut forged = tampered(&f.shards, 0, &cells);
    let teardown = [
        (PolyAddress::Memory(0), 1, int(ts)),
        (PolyAddress::Memory(1), 1, int(7)),
    ];
    forged[1] = with_cells(&f.shards[1], &teardown);
    let expected = Surface {
        reconciles: false,
        ..honest()
    };
    assert_eq!(surface(&f, &forged, &f.finals), expected);

    let unmasked = unmasked_image_window();
    let swap = |statement: &[Shard]| {
        let mut statement = statement.to_vec();
        statement[1].artifact = unmasked.clone();
        statement
    };
    assert_eq!(surface(&f, &swap(&f.shards), &f.finals), honest());
    assert_eq!(surface(&f, &swap(&forged), &f.finals), honest());
}

/// Control C2, and acceptance 7's refusal of a duplicated window: the window
/// rules on fib's statement at `h = 2^16`, shard counts from `plan_shards`, one
/// `INIT_TEARDOWN` shard and the window list `[8191]`, which passes. Each single
/// change is refused by its rule: id 0 in `ZERO_WINDOWS`, the id
/// `2^29 / h = 8192`, `[8191, 8191]`, the descending `[8191, 1]`, two
/// `INIT_TEARDOWN` shards, and two `ZERO_WINDOWS` shards over a one-id list.
/// `crates/program/tests/config.rs`' `the_window_rules_hold_at_their_boundaries`
/// holds each rule at its unit boundary. Fails if a rule is not checked.
#[test]
fn window_rules_refuse_each_single_change_of_fibs_statement() {
    let t = traced("fib", 24);
    let windows = init_windows(&t.log, HEIGHT);
    assert_eq!(windows, [STACK_WINDOW]);
    let check = |init, zero, windows: &[u32]| {
        check_memory_windows(&t.config, &counts(&t, init, zero), windows)
    };
    assert_eq!(check(1, 1, &windows), Ok(()));
    let refused = |rule| Err(ProgramError::WindowRule { rule });
    let range = "every window id is in [1, 2^29 / h - 1]";
    let increasing = "the window ids are strictly increasing";
    let one = "INIT_TEARDOWN proves exactly one shard";
    let length = "the window list has one id per ZERO_WINDOWS shard";
    assert_eq!(check(1, 1, &[0]), refused(range));
    assert_eq!(check(1, 1, &[8192]), refused(range));
    assert_eq!(check(1, 2, &[8191, 8191]), refused(increasing));
    assert_eq!(check(1, 2, &[8191, 1]), refused(increasing));
    assert_eq!(check(2, 1, &windows), refused(one));
    assert_eq!(check(1, 2, &windows), refused(length));
}

/// Control C3, the boundary. Against fib's honest roots, which reconcile with
/// `build_boundary_finals` at the image's entry pc: `x2`'s final timestamp
/// moved by one, `x10`'s final value — the exit status — set to 1, and the entry
/// pc moved by 4 each do not reconcile. Fails if `boundary_factors` did not read
/// that scalar.
#[test]
fn a_changed_boundary_scalar_does_not_reconcile() {
    let f = fib();
    let (reads, writes) = roots(&f.shards);
    let check = |entry, finals: &BoundaryFinals| {
        reconciles(&reads, &writes, boundary_factors(&f.memory, entry, finals))
    };
    let entry = f.t.image.entry;
    assert!(check(entry, &f.finals));
    let mut ts = f.finals;
    ts.reg_ts[2] += 1;
    assert!(!check(entry, &ts));
    let mut value = f.finals;
    assert_eq!(value.reg_values[9], 0);
    value.reg_values[9] = 1;
    assert!(!check(entry, &value));
    assert!(!check(entry + 4, &f.finals));
}

/// `t`'s log without its last cycle, the exit row, rebuilt by `from_events`.
fn prefix(t: &Traced) -> MemoryEventLog {
    let last = *t.cycles.last().expect("a cycle");
    let events = t.log.events().iter().filter(|e| e.cycle() < last);
    MemoryEventLog::from_events(events.copied().collect())
}

/// Control C4, halting, the prover's half: fib's log without its exit row,
/// rebuilt with `from_events` — a consistent log, as every prefix of an
/// execution is — ends with a pc write that is not `HALT_PC`, and
/// `build_boundary_finals` refuses it naming `HALT_PC`. Fails if the builder
/// filled finals for a trace that did not exit.
#[test]
#[should_panic(expected = "not HALT_PC")]
fn the_finals_refuse_a_trace_stopped_before_its_exit_row() {
    let t = traced("fib", 24);
    build_boundary_finals(&prefix(&t));
}

/// Control C4, halting, the verifier's half: the same prefix's statement — its
/// frame over cycles 1 to 2,116, its windows, and finals written by hand from
/// its final state, as a prover claiming `HALT_PC` would carry them — does not
/// reconcile: the verifier fixes the pc's final value to `HALT_PC`, and the
/// prefix's last pc write is the exit row's pc. With that one boundary tuple
/// read at the prefix's own final pc instead, it reconciles — without the
/// sentinel every prefix balances (`docs/spec/memory.md` §5). Fails if
/// `boundary_factors` did not fix the pc's final value.
#[test]
fn a_prefix_claiming_halt_pc_does_not_reconcile() {
    let t = traced("fib", 24);
    let memory = memory_challenges();
    let log = prefix(&t);
    let cycles = &t.cycles[..t.cycles.len() - 1];
    let height = cycles.len().next_power_of_two();
    let mut shards = vec![frame_shard(&log, cycles, height, &memory)];
    shards.push(window_shard(&log, &t.image, 0, &memory));
    for w in init_windows(&log, HEIGHT) {
        shards.push(window_shard(&log, &t.image, w, &memory));
    }
    let mut finals = BoundaryFinals {
        reg_ts: [0; 32],
        pc_ts: 0,
        reg_values: [0; 31],
    };
    let mut pc = HALT_PC;
    for v in log.final_state() {
        let r = v.addr as usize;
        match v.space {
            AddressSpace::Reg if r > 0 => {
                (finals.reg_ts[r], finals.reg_values[r - 1]) = (v.ts, v.value)
            }
            AddressSpace::Reg => finals.reg_ts[0] = v.ts,
            AddressSpace::Pc => (finals.pc_ts, pc) = (v.ts, v.value),
            AddressSpace::Ram => {}
        }
    }
    assert_ne!(pc, HALT_PC);
    let (reads, writes) = roots(&shards);
    let (w_b, r_b) = boundary_factors(&memory, t.image.entry, &finals);
    assert!(!reconciles(&reads, &writes, (w_b, r_b)));
    let pc_tuple = |value: u32| {
        tuple(
            &memory,
            address_space::PC,
            0,
            finals.pc_ts,
            int(value as u64),
        )
    };
    let own = r_b * pc_tuple(HALT_PC).inverse().expect("nonzero") * pc_tuple(pc);
    assert!(reconciles(&reads, &writes, (w_b, own)));
}

/// Control C5, mask booleanity (`docs/spec/memory.md` §2.4). On fib's first
/// padding row, row 2,117, the pc query forged with mask −1: address 10,
/// reading `x10`'s last write and writing 42 at `4·2,118`, the row's cycle set
/// to 2,118, with the boundary claiming `x10` ends at 42 there — the exit
/// status. At `m = −1` each of the query's two leaves is `−T(AS − 2, …)`: the pc
/// query reads and writes as a REG query, one sign flip on each side of the
/// equation, so the roots reconcile and every obligation holds. A single query's
/// read and write pair suffices; a second −1 query is not needed. `gkr::self_check`
/// names `pc_mask_boolean` on that row, the one gate that stops it; the same
/// forgery at mask 1, a PC query, does not reconcile.
///
/// Fails if the booleanity gate were missing — which the construction refuses,
/// `crates/constraints/tests/memory.rs`' `a_frame_missing_a_booleanity_gate_is_refused`.
#[test]
fn a_pc_query_masked_by_minus_1_reads_as_a_register_and_only_booleanity_refuses_it() {
    let f = fib();
    let row = f.t.cycles.len();
    let cycle = row as u64 + 1;
    let ts = TS_STEP * cycle;
    let (t10, v10) = (f.finals.reg_ts[10], f.finals.reg_values[9]);
    assert!(t10 < ts && ts - t10 - 1 < 1 << 19);
    let cells = |mask: Fr| {
        [
            (CYCLE, row, int(cycle)),
            (frame(PC, FIELD_MASK), row, mask),
            (frame(PC, FIELD_ADDR), row, int(10)),
            (frame(PC, FIELD_READ_TS), row, int(t10)),
            (frame(PC, FIELD_READ_VALUE), row, int(v10 as u64)),
            (frame(PC, FIELD_WRITE_VALUE), row, int(42)),
        ]
    };
    let mut finals = f.finals;
    finals.reg_ts[10] = ts;
    finals.reg_values[9] = 42;
    let gate = SelfCheckError {
        layer: 0,
        row,
        relation: "pc_mask_boolean".to_string(),
    };
    let expected = Surface {
        gate: Err(gate),
        lookups: Vec::new(),
        reconciles: true,
    };
    let forged = tampered(&f.shards, 0, &cells(Fr::MINUS_ONE));
    assert_eq!(surface(&f, &forged, &finals), expected);
    let as_pc = tampered(&f.shards, 0, &cells(Fr::ONE));
    let expected = Surface {
        reconciles: false,
        ..honest()
    };
    assert_eq!(surface(&f, &as_pc, &finals), expected);
}

/// Control C6, why `MEMORY_BOUNDARY` precedes the squeeze
/// (`docs/spec/memory.md` §6.1) — a documentation test. Acceptance 2's
/// unbalanced statement, with the challenges already drawn: `x10`'s final value
/// solved as `v = (T − γ_M − REG − α_addr·10 − α_ts·t_10)/α_val`, `T` being the
/// tuple that closes the equation. With `x10`'s boundary tuple at `v` the roots
/// reconcile, as they would for any trace; and `v` is not below `2^32`, so the
/// verifier's decoding of the boundary refuses it and `BoundaryFinals` cannot
/// hold it. A final value absorbed after the squeeze would have that range
/// check alone standing between a prover and this. Fails if the solved value
/// were a `u32` — about `2^32/p ≈ 2^−222` for a fresh draw; the draw here is
/// fixed.
#[test]
fn a_final_value_solved_after_the_challenges_reconciles_and_is_not_a_u32() {
    let f = fib();
    let row = first_live(&f, RAM);
    let value = cell(&f.shards[0], frame(RAM, FIELD_READ_VALUE), row) + Fr::ONE;
    let unbalanced = tampered(&f.shards, 0, &[(frame(RAM, FIELD_READ_VALUE), row, value)]);
    let (reads, writes) = roots(&unbalanced);
    let (w_b, r_b) = boundary_factors(&f.memory, f.t.image.entry, &f.finals);
    assert!(!reconciles(&reads, &writes, (w_b, r_b)));

    let product = |roots: &[Fr]| roots.iter().fold(Fr::ONE, |acc, r| acc * *r);
    let needed = product(&writes) * w_b * product(&reads).inverse().expect("nonzero");
    let (reg, t10) = (address_space::REG, f.finals.reg_ts[10]);
    let honest10 = tuple(&f.memory, reg, 10, t10, int(f.finals.reg_values[9] as u64));
    let rest = r_b * honest10.inverse().expect("nonzero");
    let target = needed * rest.inverse().expect("nonzero");
    let c = |slot| f.memory.get(slot).expect("a drawn slot");
    let known =
        c(MEM_GAMMA) + int(reg as u64) + c(MEM_ALPHA_ADDR) * int(10) + c(MEM_ALPHA_TS) * int(t10);
    let v = (target - known) * c(MEM_ALPHA_VAL).inverse().expect("nonzero");
    let solved = rest * tuple(&f.memory, reg, 10, t10, v);
    assert!(reconciles(&reads, &writes, (w_b, solved)));
    assert!(
        v.to_bytes()[4..].iter().any(|b| *b != 0),
        "the solved value is not a u32"
    );
}
