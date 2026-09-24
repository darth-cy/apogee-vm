//! S14's acceptance items and the design's controls, over a real execution:
//! fib's committed ELF traced with every family at `h = 2^16` — one frame per
//! family that ran, each over that family's cycles at the smallest power-of-two
//! height holding them, `INIT_TEARDOWN`'s window 0, `ZERO_WINDOWS`' stack
//! window 8191, and its boundary — each tampered as an adversarial prover
//! would, beside its honest twin. "Does not reconcile" means: the tampered base
//! forwarded honestly, its roots recomputed by `memory_roots`, and
//! `gkr::reconciles` false. Where a tamper breaks a gate, `gkr::self_check`
//! names it.
//!
//! **A frame holds only its family's queries** (`docs/spec/memory.md` §2.1), so
//! a column is addressed by its *slot* — its position in
//! `constraints::memory::frame_queries(family)` — and not by a query id. Each
//! tamper below names the family whose frame it edits and the slot it aims at,
//! and a query no one frame has is reached in whichever family's frame has it:
//! `arg1` and `arg2` in `ADD_SUB_LUI_AUIPC`'s, `load` in `MEM_WORD`'s.
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
    cell, forwarded_shard, frame_height, frame_plan, frame_shard, memory_challenges,
    prove_and_verify, reconciled, roots, shards, traced, window_shard, window_shards, with_cells,
    witness_row, Shard, Traced, GUESTS, HEIGHT,
};
use constants::challenge_slot::{
    MEM_ALPHA_ADDR, MEM_ALPHA_TS, MEM_ALPHA_VAL, MEM_GAMMA, MEM_WINDOW_CONSTANT,
};
use constants::memory::{HALT_PC, TS_STEP};
use constants::{address_space, family};
use constraints::memory::{
    check_memory, family_frame_artifact, frame, frame_queries, gap_hi, image_window_artifact,
    rd_inv, rd_is_zero, rd_selected, zero_window_artifact, CYCLE, FIELD_ADDR, FIELD_MASK,
    FIELD_READ_TS, FIELD_READ_VALUE, FIELD_WRITE_VALUE, FRAME_DELTA, FRAME_NAMES, FRAME_READ_ONLY,
    FRAME_SPACE, LOAD, PC, RAM, RD, RS1, RS2,
};
use constraints::{CircuitArtifact, Coeff, GateDef, PolyAddress, VirtualKind};
use field::Fr;
use gkr::{
    boundary_factors, reconciles, self_check, window_challenges, BaseLayer, BoundaryFinals,
    ExternalChallenges, SelfCheckError,
};
use loader::ProgramImage;
use poly::{MultilinearPoly, PolyBacking};
use program::{check_memory_windows, ProgramError};
use trace::{
    build_boundary_finals, init_windows, plan_shards, AddressSpace, MemoryEvent, MemoryEventLog,
};

/// fib's six frame shards, in `shards` order — the families that ran,
/// ascending — then its two windows, then the two delegation families its exit
/// invokes. `fib` pins the whole list.
///
/// It was five frames and no delegation until S25. `fib` reads fd 0 and
/// commits to fd 1, so it now computes `io_digest` at exit
/// (`docs/spec/memory.md` §10): that brings in `MUL_DIV`, and on the guest
/// target it routes Poseidon2 and `Fr`'s arithmetic through their delegations,
/// whose invocations need shards of their own for the anchors to pair.
const ALU: usize = 0;
const JUMP: usize = 1;
const MEM: usize = 4;
/// How many frames fib's statement has; the windows follow them.
const FRAMES: usize = 6;
/// `INIT_TEARDOWN`'s shard, RAM window 0.
const WINDOW_0: usize = FRAMES;
/// The `ZERO_WINDOWS` shard of fib's stack window.
const STACK: usize = FRAMES + 1;

/// fib's stack window at `h = 2^16`: `2^29 / h − 1`.
const STACK_WINDOW: u32 = 8191;

fn int(v: u64) -> Fr {
    Fr::from_u64(v)
}

/// fib's honest statement: its trace, slots 1–4, its frame plan, its seven
/// shards — one frame per family that ran, then window 0 and the stack window,
/// in that order — and its finals.
struct Fib {
    t: Traced,
    memory: ExternalChallenges,
    /// Each frame shard's family and the cycles it proves, `shards`-aligned.
    plan: Vec<(u32, Vec<u64>)>,
    shards: Vec<Shard>,
    finals: BoundaryFinals,
}

fn fib() -> Fib {
    let t = traced("fib", 24);
    let memory = memory_challenges();
    let plan = frame_plan(&t);
    let shards = shards(&t, &memory);
    let labels: Vec<&str> = shards.iter().map(|s| s.label.as_str()).collect();
    assert_eq!(
        labels,
        [
            "frame of add_sub_lui_auipc",
            "frame of jump_branch_slt",
            "frame of shift_bitwise",
            "frame of mul_div",
            "frame of mem_word",
            "frame of mem_subword",
            "window 0",
            "window 8191",
            "delegation family 10",
            "delegation family 11",
        ]
    );
    let families: Vec<u32> = plan.iter().map(|(id, _)| *id).collect();
    assert_eq!(
        families,
        [
            family::ADD_SUB_LUI_AUIPC,
            family::JUMP_BRANCH_SLT,
            family::SHIFT_BITWISE,
            family::MUL_DIV,
            family::MEM_WORD,
            family::MEM_SUBWORD,
        ]
    );
    assert_eq!(plan.len(), FRAMES);
    let finals = build_boundary_finals(&t.log);
    Fib {
        t,
        memory,
        plan,
        shards,
        finals,
    }
}

/// `shards` with each `(shard, address, row, value)` of `cells` written into
/// that shard's base, every other cell as it is. A forgery spanning two
/// families' frames — two `rd` writes to one register that consecutive cycles
/// of different families made — is one call.
fn tampered(shards: &[Shard], cells: &[(usize, PolyAddress, usize, Fr)]) -> Vec<Shard> {
    let mut out = shards.to_vec();
    for (i, shard) in out.iter_mut().enumerate() {
        let mine: Vec<(PolyAddress, usize, Fr)> = cells
            .iter()
            .filter(|c| c.0 == i)
            .map(|c| (c.1, c.2, c.3))
            .collect();
        if !mine.is_empty() {
            *shard = with_cells(shard, &mine);
        }
    }
    out
}

/// What a statement breaks: the first gate `gkr::self_check` names, shard by
/// shard; every `(row, obligation)` `violated_lookups` names on any frame; and
/// whether the roots reconcile with `finals`. Every frame is swept, so an
/// obligation broken in any family's is reported.
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
    for shard in shards {
        let a = &shard.artifact;
        let values = forwarded_shard(shard);
        if gate.is_ok() {
            gate = self_check(a, &values, &shard.challenges);
        }
        let (read, write) =
            memory_roots(a, &values).unwrap_or_else(|e| panic!("{}: {e}", shard.label));
        reads.push(read);
        writes.push(write);
        if shard.family.is_some() {
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

/// Shard `i`'s frame width, `w = frame_queries(family).len()`, which is where
/// the x0 gadget's three witness columns start.
fn width(f: &Fib, i: usize) -> usize {
    frame_queries(f.shards[i].family.expect("a frame shard")).len()
}

/// Query `q`'s slot in shard `i`'s frame, if that family holds it at all.
fn slot(f: &Fib, i: usize, q: usize) -> Option<usize> {
    let queries = frame_queries(f.shards[i].family.expect("a frame shard"));
    queries.iter().position(|&x| x == q)
}

/// The frame shard and the row holding `cycle`: each cycle is in exactly one
/// family's frame, at its place in that family's cycle list.
fn at_cycle(f: &Fib, cycle: u64) -> (usize, usize) {
    for (i, (_, cycles)) in f.plan.iter().enumerate() {
        if let Some(row) = cycles.iter().position(|&c| c == cycle) {
            return (i, row);
        }
    }
    panic!("no frame of fib's statement holds cycle {cycle}")
}

/// The frame shard, row and slot holding `e`: its cycle's frame and row, and
/// the live query there of its space and slot at its address reading its
/// timestamp.
fn locate(f: &Fib, e: &MemoryEvent) -> (usize, usize, usize) {
    let (i, row) = at_cycle(f, e.cycle());
    let queries = frame_queries(f.shards[i].family.expect("a frame shard"));
    let holds = |at: usize| {
        let q = queries[at];
        FRAME_SPACE[q] == e.space.tag()
            && FRAME_DELTA[q] == e.delta()
            && cell(&f.shards[i], frame(at, FIELD_MASK), row) == Fr::ONE
            && cell(&f.shards[i], frame(at, FIELD_ADDR), row) == int(e.addr as u64)
            && cell(&f.shards[i], frame(at, FIELD_READ_TS), row) == int(e.read_ts)
    };
    let at = (0..queries.len()).find(|&at| holds(at));
    (
        i,
        row,
        at.unwrap_or_else(|| panic!("the frame holds {e:?}")),
    )
}

/// The first frame of fib's statement holding query `q`, with its first live
/// row there and `q`'s slot in it. A query no one family has is found in
/// whichever family's frame has it.
fn first_live(f: &Fib, q: usize) -> (usize, usize, usize) {
    for i in 0..FRAMES {
        let Some(at) = slot(f, i, q) else { continue };
        let live = |y: &usize| cell(&f.shards[i], frame(at, FIELD_MASK), *y) == Fr::ONE;
        if let Some(row) = (0..f.plan[i].1.len()).find(live) {
            return (i, row, at);
        }
    }
    panic!("no frame of fib's statement has a live {}", FRAME_NAMES[q])
}

/// The same for the first *live row without* `q`: a row whose instruction does
/// not make that query, in a family whose frame has a column for it.
fn first_empty(f: &Fib, q: usize) -> (usize, usize, usize) {
    for i in 0..FRAMES {
        let Some(at) = slot(f, i, q) else { continue };
        let empty = |y: &usize| cell(&f.shards[i], frame(at, FIELD_MASK), *y) == Fr::ZERO;
        if let Some(row) = (0..f.plan[i].1.len()).find(empty) {
            return (i, row, at);
        }
    }
    panic!("every live row of fib has a {}", FRAME_NAMES[q])
}

/// The first two queries of one register, taken in register order, that are
/// both `rd` writes — no query of the register between them — and that `keep`
/// accepts. The two need not be in one family's frame.
fn rd_writes_in_a_row(f: &Fib, keep: impl Fn(&MemoryEvent) -> bool) -> (MemoryEvent, MemoryEvent) {
    let rd = |e: &MemoryEvent| e.delta() == FRAME_DELTA[RD];
    for r in 0..32 {
        let on_r: Vec<MemoryEvent> = (f.t.log.events().iter().copied())
            .filter(|e| e.space == AddressSpace::Reg && e.addr == r)
            .collect();
        let pair = on_r
            .windows(2)
            .find(|p| rd(&p[0]) && rd(&p[1]) && keep(&p[0]));
        if let Some(p) = pair {
            return (p[0], p[1]);
        }
    }
    panic!("fib has no such pair of rd writes");
}

/// `forged` keeps every obligation and reconciles, and shard `i`'s frame breaks
/// exactly `relation` on `row`: `gkr::self_check` names it, and it is the one
/// relation the witness-row evaluator reports there.
fn balanced_and_refused_by(f: &Fib, forged: &[Shard], i: usize, row: usize, relation: &str) {
    let gate = SelfCheckError {
        layer: 0,
        row,
        relation: relation.to_string(),
    };
    let expected = Surface {
        gate: Err(gate),
        lookups: Vec::new(),
        reconciles: true,
    };
    assert_eq!(surface(f, forged, &f.finals), expected, "{relation}");
    let (a, challenges) = (&forged[i].artifact, &forged[i].challenges);
    let w = witness_row(a, &forwarded_shard(&forged[i]), row);
    assert_eq!(violated_relations(a, &w, challenges), [relation]);
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

/// S14 acceptance 2, one value. fib's first RAM store — its `ram` query, at
/// slot 4 of `MEM_WORD`'s frame — reads the word it overwrites; that read value
/// moved by one leaves every gate and every obligation holding, since none reads
/// a store's read value, and the roots do not reconcile: the read tuple is no
/// write's. The honest twin keeps every gate and obligation and reconciles. A
/// value tamper's failure surface is reconciliation alone.
///
/// Fails if the frame's read leaf did not bind `read_value`.
#[test]
fn one_changed_value_does_not_reconcile() {
    let f = fib();
    assert_eq!(surface(&f, &f.shards, &f.finals), honest());
    let store =
        f.t.log
            .events()
            .iter()
            .copied()
            .find(|e| e.space == AddressSpace::Ram && e.delta() == FRAME_DELTA[RAM])
            .expect("a store");
    let (i, row, at) = locate(&f, &store);
    assert_eq!(
        (i, at),
        (MEM, slot(&f, MEM, RAM).expect("mem_word has ram"))
    );
    let value = cell(&f.shards[i], frame(at, FIELD_READ_VALUE), row) + Fr::ONE;
    let forged = tampered(&f.shards, &[(i, frame(at, FIELD_READ_VALUE), row, value)]);
    let expected = Surface {
        reconciles: false,
        ..honest()
    };
    assert_eq!(surface(&f, &forged, &f.finals), expected);
}

/// S14 acceptance 3, one timestamp, in both of its places on row 11 of
/// `ADD_SUB_LUI_AUIPC`'s frame, cycle 18:
///
/// - its pc query's read timestamp moved one earlier, 68 to 67, with `gap_hi`
///   rewritten for the new gap (it stays 0): no gate and no obligation breaks,
///   and the roots do not reconcile — acceptance 2's surface;
/// - its cycle moved one earlier, 18 to 17, which moves every write timestamp
///   of the row four earlier: the roots do not reconcile, and the lookup
///   evaluator also names, on that row, the low chunk of every live query whose
///   gap was below 4 and went negative — measured: the pc query's, whose gap is
///   always 3, and `rs1`'s.
///
/// So the surfaces differ: a value enters no obligation, and a timestamp that
/// moves a gap below 0 is caught by the lookup evaluator as well as by
/// reconciliation. The row is pinned because the second half's short set is a
/// measurement, not a rule. Fails if the read leaf did not bind `read_ts`, the
/// write leaf `cycle`, or the gap obligations `cycle`.
#[test]
fn one_changed_timestamp_does_not_reconcile_and_a_moved_cycle_breaks_a_gap() {
    let f = fib();
    const ROW: usize = 11;
    const CYCLE_AT_ROW: u64 = 18;
    assert_eq!(cell(&f.shards[ALU], CYCLE, ROW), int(CYCLE_AT_ROW));
    let pc = slot(&f, ALU, PC).expect("every frame has the pc query");
    let read_ts = frame(pc, FIELD_READ_TS);
    assert_eq!(cell(&f.shards[ALU], read_ts, ROW), int(68));
    let gap = TS_STEP * CYCLE_AT_ROW - 67 - 1;
    let cells = [
        (ALU, read_ts, ROW, int(67)),
        (ALU, gap_hi(pc), ROW, int(gap >> 19)),
    ];
    let expected = Surface {
        reconciles: false,
        ..honest()
    };
    assert_eq!(
        surface(&f, &tampered(&f.shards, &cells), &f.finals),
        expected
    );

    let queries = frame_queries(family::ADD_SUB_LUI_AUIPC);
    let at = |at: usize, field| small(cell(&f.shards[ALU], frame(at, field), ROW));
    let short: Vec<String> = (0..queries.len())
        .filter(|&s| at(s, FIELD_MASK) == 1)
        .filter(|&s| {
            let delta = FRAME_DELTA[queries[s]];
            TS_STEP * CYCLE_AT_ROW + delta - at(s, FIELD_READ_TS) - 1 < TS_STEP
        })
        .map(|s| format!("gap_lo_{}", FRAME_NAMES[queries[s]]))
        .collect();
    assert_eq!(short, ["gap_lo_pc", "gap_lo_rs1"]);
    let forged = tampered(&f.shards, &[(ALU, CYCLE, ROW, int(CYCLE_AT_ROW - 1))]);
    let expected = Surface {
        gate: Ok(()),
        lookups: short.into_iter().map(|name| (ROW, name)).collect(),
        reconciles: false,
    };
    assert_eq!(surface(&f, &forged, &f.finals), expected);
}

/// S14 acceptance 4, the future-read attack. fib's first three queries of
/// `x0`, Q1 < Q2 < Q3, each an `rs1` read of 0 written back, all three in
/// `ADD_SUB_LUI_AUIPC`'s frame at slot 1: Q1 reads the init at 0, Q2 reads Q1's
/// write and Q3 Q2's. Swapping Q1's and Q3's read timestamps permutes the read
/// multiset, so the multisets balance and the roots reconcile — while Q1 now
/// reads Q2's write, from its own future. No gate reads a read timestamp, so
/// `gkr::self_check` passes; the lookup evaluator names exactly `gap_lo_rs1` on
/// Q1's row, whose gap `4·cycle + Δ − read_ts − 1` is negative, and no high
/// chunk rescues it: every `gap_hi` tried, from 1 to `−1`, names an obligation
/// too.
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
    let (i1, r1, k1) = locate(&f, &q1);
    let (i3, r3, k3) = locate(&f, &q3);
    let rs1 = slot(&f, ALU, RS1).expect("rs1 is in every frame");
    assert_eq!((i1, k1, i3, k3), (ALU, rs1, ALU, rs1));
    let cells = [
        (i1, frame(k1, FIELD_READ_TS), r1, int(q3.read_ts)),
        (i3, frame(k3, FIELD_READ_TS), r3, int(q1.read_ts)),
    ];
    let forged = tampered(&f.shards, &cells);
    let expected = Surface {
        gate: Ok(()),
        lookups: vec![(r1, "gap_lo_rs1".to_string())],
        reconciles: true,
    };
    assert_eq!(surface(&f, &forged, &f.finals), expected);

    let a = &forged[i1].artifact;
    let honest_row = witness_row(a, &forwarded_shard(&forged[i1]), r1);
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
/// `load`, which only `MEM_WORD`'s and `MEM_SUBWORD`'s frames have, and which
/// writes back what it read. One of its bytes flipped in the `ProgramImage`,
/// and window 0's columns, `S[0]` and teardown, rebuilt from the flipped image
/// beside the honest trace: the roots do not reconcile, because the init tuple
/// no longer holds the value the read consumed. The same flip in a word nothing
/// touches, the entry instruction's first byte, reconciles: that row's init and
/// teardown are both the flipped image's word and cancel — which is why the
/// test flips a word the trace reads.
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
    assert_eq!(locate(&f, read).0, MEM, "a load is in MEM_WORD's frame");
    let mut statement = f.shards.clone();
    let image = flipped(&f.t.image, read.addr);
    assert_ne!(image.initial_word(read.addr), read.read_value);
    statement[WINDOW_0] = window_shard(&f.t.log, &image, 0, &f.memory);
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
    statement[WINDOW_0] = window_shard(&f.t.log, &image, 0, &f.memory);
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
    let stack = &f.shards[STACK];
    let window = |value: Fr| {
        let mut init = vec![Fr::ZERO; HEIGHT as usize];
        init[window_row(first.addr, STACK_WINDOW)] = value;
        let mut columns: Vec<(PolyAddress, MultilinearPoly)> = [0, 1]
            .map(|m| (PolyAddress::Memory(m), cell_column(stack, m)))
            .into();
        columns.push((init_value, column(init)));
        Shard {
            label: "forged window 8191".to_string(),
            family: None,
            artifact: forged.clone(),
            base: BaseLayer::new(columns),
            challenges: stack.challenges.clone(),
        }
    };
    for (value, balances) in [(Fr::ZERO, true), (int(7), false)] {
        let mut statement = f.shards.clone();
        statement[STACK] = window(value);
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
/// nonzero value, at `0x7fffff70` — a `ram` query at slot 4 of `MEM_WORD`'s
/// frame — made stale: it reads the init `(0, 0)` instead of the last write
/// `(195, 0x12728)`. Against the honest statement no gate or obligation breaks
/// and the roots do not reconcile. With a second `ZERO_WINDOWS` shard for window
/// 8191 — every word of the window given an init row twice — holding that last
/// write as teardown on the word's row and zeros elsewhere, the stale read
/// consumes the second init, the orphaned write the second teardown, every
/// other row cancels, and the roots reconcile with nothing broken.
/// `check_memory_windows` refuses the list `[8191, 8191]`
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
    let (i, row, at) = locate(&f, stale);
    assert_eq!(
        (i, at),
        (MEM, slot(&f, MEM, RAM).expect("mem_word has ram"))
    );
    let cells = [
        (i, frame(at, FIELD_READ_TS), row, Fr::ZERO),
        (i, frame(at, FIELD_READ_VALUE), row, Fr::ZERO),
    ];
    let mut statement = tampered(&f.shards, &cells);
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
    let stack = &f.shards[STACK];
    statement.push(Shard {
        label: "window 8191, twice".to_string(),
        family: None,
        artifact: stack.artifact.clone(),
        base: BaseLayer::new(vec![
            (PolyAddress::Memory(0), column(ts)),
            (PolyAddress::Memory(1), column(value)),
        ]),
        challenges: stack.challenges.clone(),
    });
    assert_eq!(surface(&f, &statement, &f.finals), honest());
}

/// S14 acceptance 8, the honest half: across every frame of fib's statement,
/// every live query at REG address 0 — `rs1`, `rs2`, `arg1`, `arg2` or `rd`,
/// wherever its family holds it — reads 0 and writes 0, and there are as many as
/// the log has `x0` queries, 432. Every frame is swept, so the count is over the
/// whole execution however the families split it. Fails if the builders or the
/// execution let `x0` hold anything but 0.
#[test]
fn every_read_of_x0_returns_0() {
    let f = fib();
    let mut x0 = 0;
    for i in 0..FRAMES {
        let queries = frame_queries(f.shards[i].family.expect("a frame shard"));
        let reg = (0..queries.len()).filter(|&s| FRAME_SPACE[queries[s]] == address_space::REG);
        for at in reg {
            for row in 0..f.plan[i].1.len() {
                let value = |field| cell(&f.shards[i], frame(at, field), row);
                if value(FIELD_MASK) == Fr::ONE && value(FIELD_ADDR) == Fr::ZERO {
                    let label = FRAME_NAMES[queries[at]];
                    assert_eq!(value(FIELD_READ_VALUE), Fr::ZERO, "{label}, row {row}");
                    assert_eq!(value(FIELD_WRITE_VALUE), Fr::ZERO, "{label}, row {row}");
                    x0 += 1;
                }
            }
        }
    }
    let log = f.t.log.events().iter();
    let expected = log.filter(|e| e.space == AddressSpace::Reg && e.addr == 0);
    assert_eq!(x0, expected.count());
    assert_eq!(x0, 432);
}

/// S14 acceptance 8, the forged half, `docs/spec/memory.md` §2.4's note. fib's
/// first two `rd` writes to `x0` with no `x0` query between them, R1 then R2,
/// both cycles of `JUMP_BRANCH_SLT`, whose frame holds `rd` at slot 3. R1's
/// write value set to 5 and R2's read value to 5: R2 consumes the 5 and writes
/// 0, so `x0` still ends at the verifier's 0, the multisets balance and the
/// roots reconcile, with every obligation holding — `v_0 = 0` alone does not
/// stop it. The x0 gadget does: `gkr::self_check` names `rd_write_masked` on
/// R1's row, the one relation the witness-row evaluator reports there.
///
/// Fails if the gadget did not mask an `rd` write at address 0.
#[test]
fn a_write_of_5_to_x0_balances_and_rd_write_masked_refuses_it() {
    let f = fib();
    let (w1, w2) = rd_writes_in_a_row(&f, |e| e.addr == 0);
    let (i1, r1, k1) = locate(&f, &w1);
    let (i2, r2, k2) = locate(&f, &w2);
    assert_eq!((i1, i2), (JUMP, JUMP));
    assert_eq!(
        (k1, k2),
        (slot(&f, JUMP, RD).unwrap(), slot(&f, JUMP, RD).unwrap())
    );
    let cells = [
        (i1, frame(k1, FIELD_WRITE_VALUE), r1, int(5)),
        (i2, frame(k2, FIELD_READ_VALUE), r2, int(5)),
    ];
    let forged = tampered(&f.shards, &cells);
    balanced_and_refused_by(&f, &forged, i1, r1, "rd_write_masked");
}

/// S14 acceptance 8, the x0 gadget's other two gates, each against the forgery
/// only it refuses, and each forgery balanced, so reconciliation cannot stand
/// in for the gate:
///
/// - `rd_is_zero_at_nonzero`: fib's first two `rd` writes in a row to one
///   nonzero register, `x11`, R1 writing a nonzero value. R1 is a cycle of
///   `ADD_SUB_LUI_AUIPC` and R2 one of `MEM_WORD`, so this forgery spans two
///   frames, `rd` sitting at slot 6 of the first and slot 5 of the second. R1
///   claims `rd_is_zero = 1` with `rd_inv = 0` and writes 0, and R2 reads that 0
///   — a register write zeroed. The inverse gate holds (`addr·0 + 1 − 1`), and
///   so does `rd_write_masked` (`0 − sel + 1·sel`).
/// - `rd_is_zero_inverse`: the pair of `rd` writes to `x0` above, both in
///   `JUMP_BRANCH_SLT`'s frame. R1 claims `rd_is_zero = 0` with
///   `rd_selected = 5` and writes 5, and R2 reads 5 — `x0` holding 5. `addr·z`
///   is 0 at address 0, and `rd_write_masked` holds, since `z = 0` selects the 5.
///
/// The three x0 witness columns follow the family's `w` gap columns, so each
/// forgery names them at its own frame's width. Each keeps every obligation and
/// reconciles, and `gkr::self_check` and the witness-row evaluator name exactly
/// that gate on R1's row. Fails if either gate were missing, or read another
/// column under its name: `rd_is_zero_at_nonzero` over `rd_inv` instead of the
/// address admits the first.
#[test]
fn a_zeroed_register_write_and_a_nonzero_x0_write_are_each_refused_by_their_gate() {
    let f = fib();
    let (w1, w2) = rd_writes_in_a_row(&f, |e| e.addr != 0 && e.write_value != 0);
    let (i1, r1, k1) = locate(&f, &w1);
    let (i2, r2, k2) = locate(&f, &w2);
    assert_eq!((i1, i2), (ALU, MEM), "the pair spans two families' frames");
    let cells = [
        (i1, rd_is_zero(width(&f, i1)), r1, Fr::ONE),
        (i1, rd_inv(width(&f, i1)), r1, Fr::ZERO),
        (i1, frame(k1, FIELD_WRITE_VALUE), r1, Fr::ZERO),
        (i2, frame(k2, FIELD_READ_VALUE), r2, Fr::ZERO),
    ];
    let forged = tampered(&f.shards, &cells);
    balanced_and_refused_by(&f, &forged, i1, r1, "rd_is_zero_at_nonzero");

    let (w1, w2) = rd_writes_in_a_row(&f, |e| e.addr == 0);
    let (i1, r1, k1) = locate(&f, &w1);
    let (i2, r2, k2) = locate(&f, &w2);
    assert_eq!((i1, i2), (JUMP, JUMP));
    let cells = [
        (i1, rd_is_zero(width(&f, i1)), r1, Fr::ZERO),
        (i1, rd_selected(width(&f, i1)), r1, int(5)),
        (i1, frame(k1, FIELD_WRITE_VALUE), r1, int(5)),
        (i2, frame(k2, FIELD_READ_VALUE), r2, int(5)),
    ];
    let forged = tampered(&f.shards, &cells);
    balanced_and_refused_by(&f, &forged, i1, r1, "rd_is_zero_inverse");
}

/// `docs/spec/memory.md` §2.4, the read-only queries. On the first live row of
/// each of `rs1`, `rs2`, `arg1`, `arg2` and `load`, in the first frame of fib's
/// statement whose family holds that query, that query's write value set to its
/// read value plus one — a read that silently changes the register or word it
/// read. `gkr::self_check` and the witness-row evaluator name exactly
/// `<q>_writes_back` on that row. All five of `FRAME_READ_ONLY` are tried, so a
/// gate built over another query's columns under the right name fails too; and
/// since no family holds all five, this crosses frames — `arg1` and `arg2` are
/// `ADD_SUB_LUI_AUIPC`'s alone and `load` `MEM_WORD`'s. Fails if a read-only
/// query could write back a value it did not read.
#[test]
fn a_read_only_query_writing_back_another_value_is_refused_by_its_gate() {
    let f = fib();
    let mut families = Vec::new();
    for q in FRAME_READ_ONLY {
        let (i, row, at) = first_live(&f, q);
        families.push(i);
        let value = cell(&f.shards[i], frame(at, FIELD_READ_VALUE), row) + Fr::ONE;
        let forged = with_cells(&f.shards[i], &[(frame(at, FIELD_WRITE_VALUE), row, value)]);
        let (a, challenges) = (&forged.artifact, &forged.challenges);
        let values = forwarded_shard(&forged);
        let relation = format!("{}_writes_back", FRAME_NAMES[q]);
        let gate = SelfCheckError {
            layer: 0,
            row,
            relation: relation.clone(),
        };
        assert_eq!(self_check(a, &values, challenges), Err(gate));
        let w = witness_row(a, &values, row);
        assert_eq!(violated_relations(a, &w, challenges), [relation]);
    }
    assert_eq!(
        families,
        [ALU, ALU, ALU, ALU, MEM],
        "five queries, two frames"
    );
}

/// S14 acceptance 10, padding. `ADD_SUB_LUI_AUIPC`'s frame at the menu height
/// 2^16 — 657 live rows and 64,879 padding rows — keeps every gate, proves,
/// verifies and discharges its base claims. Every committed cell of every
/// padding row is the artifact's padding row, all zeros, `cycle` included
/// (`docs/spec/memory.md` §2.1). On every padding row each of the 16 leaves —
/// 14 for the family's seven queries and two constant-1 pad leaves, 8 a side —
/// and every row-wise product above them, is exactly 1 in the forwarded values;
/// so its roots are the 2^10 frame's, and they reconcile with fib's other frames
/// and windows. `check_padding_identity` holds the artifact to the same clause.
/// Fails if any padding cell were not 0 — a cycle filled on a padding row past
/// the first, which no leaf sees on a mask-0 row — or if a masked leaf were not
/// 1: a padding row would move a root. The row-wise depth is read from the
/// artifact, so a family whose leaves need fewer lists is measured, not assumed.
#[test]
fn the_frame_padded_to_2_16_proves_and_its_padding_rows_are_1() {
    let f = fib();
    let (family, cycles) = &f.plan[ALU];
    let live = cycles.len();
    assert_eq!(live, 657);
    let tall = frame_shard(&f.t.log, *family, cycles, 1 << 16, &f.memory);
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
    let row_wise = tall
        .artifact
        .layers
        .iter()
        .take_while(|l| !l.halving)
        .count();
    assert_eq!(
        row_wise, 4,
        "16 leaves take three row-wise lists above them"
    );
    for (k, layer) in values.layers[..row_wise].iter().enumerate() {
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
    let short = forwarded_shard(&f.shards[ALU]);
    assert_eq!(
        memory_roots(&tall.artifact, &values),
        memory_roots(&f.shards[ALU].artifact, &short)
    );
    let mut statement = f.shards.clone();
    statement[ALU] = tall.clone();
    assert!(reconciled(
        &statement,
        &f.memory,
        f.t.image.entry,
        &f.finals
    ));
    assert_eq!(check_padding_identity(&tall.artifact), Ok(()));
    assert_eq!(prove_and_verify(&tall, &values), Ok(()));
}

/// S14 acceptance 11, the full-width boundary: `ADD_SUB_LUI_AUIPC`'s own `rs1`
/// obligations through `violated_lookups`, on a row at cycle `2^36`, where
/// `gap = 4·2^36 + 1 − read_ts − 1 = 2^38 − read_ts`. `rs1` is slot 1 of every
/// family's frame. Gaps 0 and `2^38 − 1` with `gap_hi = gap >> 19` are accepted;
/// gaps −1 and `2^38` are refused with every `gap_hi` tried — 0, 1, `2^19 − 1`,
/// `2^19` and `−1`. The exhaustive statement over every high chunk is the
/// reduced-width test `crates/constraints/tests/memory.rs`'
/// `the_gap_encoding_is_strict_at_reduced_width`. Fails if the chunk bound were
/// not `2^19`, or the low chunk not the gap less `2^19·hi`.
#[test]
fn the_gap_obligations_accept_exactly_0_through_2_38_minus_1() {
    let a = family_frame_artifact(family::ADD_SUB_LUI_AUIPC, 4);
    let rs1 = frame_queries(family::ADD_SUB_LUI_AUIPC)
        .iter()
        .position(|&q| q == RS1)
        .expect("rs1 is in every frame");
    let layout = a.committed();
    let at = |address| layout.iter().position(|c| *c == address).expect("a column");
    let top = int(1 << 38);
    let row = |gap: Fr, hi: Fr| {
        let mut committed = vec![Fr::ZERO; layout.len()];
        committed[at(CYCLE)] = int(1 << 36);
        committed[at(frame(rs1, FIELD_MASK))] = Fr::ONE;
        committed[at(frame(rs1, FIELD_READ_TS))] = top - gap;
        committed[at(gap_hi(rs1))] = hi;
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

/// Control C1, the head mask and `id ≥ 1`, the two rules that keep an access
/// below `RAM_ORIGIN` from balancing (`docs/spec/memory.md` §9). On the first
/// live row with no `ram` query in a frame whose family has one — measured:
/// `ADD_SUB_LUI_AUIPC`'s, where `ram` is slot 5 and only an ecall transfer row
/// uses it — a forged `ram` query at word `0x4`, below `RAM_ORIGIN` and window
/// 0's row 1, reading `(0, 0)` and writing 7, with window 0's teardown row 1 set
/// to that write: every gate and obligation holds, and the roots do not
/// reconcile, because `V[ram_live]` makes row 1's leaves 1 and leaves no init
/// tuple for the read to consume. The same forgery against the unmasked window 0
/// reconciles; that variant with fib's honest trace reconciles too, so the mask
/// is the only difference. And with window 0 honest but a `ZERO_WINDOWS` shard
/// listed at id 0, which has no mask, it reconciles as well.
///
/// Fails if `V[ram_live]` did not remove window 0's rows below `RAM_ORIGIN`, or
/// if a zero window at id 0 were not a real attack and its rule not load-bearing.
#[test]
fn a_query_below_ram_origin_balances_only_without_the_head_mask() {
    let f = fib();
    let (i, row, at) = first_empty(&f, RAM);
    assert_eq!(
        (i, at),
        (ALU, slot(&f, ALU, RAM).expect("the alu frame has ram"))
    );
    for address in [
        frame(at, FIELD_ADDR),
        frame(at, FIELD_READ_TS),
        frame(at, FIELD_READ_VALUE),
        gap_hi(at),
    ] {
        assert_eq!(cell(&f.shards[i], address, row), Fr::ZERO, "{address}");
    }
    let cycle = small(cell(&f.shards[i], CYCLE, row));
    let ts = TS_STEP * cycle + FRAME_DELTA[RAM];
    let cells = [
        (i, frame(at, FIELD_MASK), row, Fr::ONE),
        (i, frame(at, FIELD_ADDR), row, int(4)),
        (i, frame(at, FIELD_WRITE_VALUE), row, int(7)),
    ];
    let mut forged = tampered(&f.shards, &cells);
    let teardown = [
        (PolyAddress::Memory(0), 1, int(ts)),
        (PolyAddress::Memory(1), 1, int(7)),
    ];
    forged[WINDOW_0] = with_cells(&f.shards[WINDOW_0], &teardown);
    let expected = Surface {
        reconciles: false,
        ..honest()
    };
    assert_eq!(surface(&f, &forged, &f.finals), expected);

    let unmasked = unmasked_image_window();
    let swap = |statement: &[Shard]| {
        let mut statement = statement.to_vec();
        statement[WINDOW_0].artifact = unmasked.clone();
        statement
    };
    assert_eq!(surface(&f, &swap(&f.shards), &f.finals), honest());
    assert_eq!(surface(&f, &swap(&forged), &f.finals), honest());

    // The id bound's other half: a ZERO_WINDOWS shard listed at window 0 has no
    // mask, so its row 1 is an init row for 0x4. With it holding the forged
    // write as teardown, zeros elsewhere, and window 0 honest, the forgery
    // reconciles too; `check_memory_windows` refuses id 0 (C2).
    let vars = HEIGHT.trailing_zeros();
    let (mut ts_column, mut value_column) = (
        vec![Fr::ZERO; HEIGHT as usize],
        vec![Fr::ZERO; HEIGHT as usize],
    );
    (ts_column[1], value_column[1]) = (int(ts), int(7));
    forged[WINDOW_0] = f.shards[WINDOW_0].clone();
    forged.push(Shard {
        label: "zero window 0".to_string(),
        family: None,
        artifact: zero_window_artifact(vars),
        base: BaseLayer::new(vec![
            (PolyAddress::Memory(0), column(ts_column)),
            (PolyAddress::Memory(1), column(value_column)),
        ]),
        challenges: window_challenges(&f.memory, 0, vars),
    });
    assert_eq!(surface(&f, &forged, &f.finals), honest());
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

/// Control C4, halting, the verifier's half: the same prefix's statement — one
/// frame per family over that family's cycles below the exit row's, its
/// windows, and finals written by hand from its final state, as a prover
/// claiming `HALT_PC` would carry them — does not reconcile: the verifier fixes
/// the pc's final value to `HALT_PC`, and the prefix's last pc write is the exit
/// row's pc. With that one boundary tuple read at the prefix's own final pc
/// instead, it reconciles — without the sentinel every prefix balances
/// (`docs/spec/memory.md` §5). Fails if `boundary_factors` did not fix the pc's
/// final value.
#[test]
fn a_prefix_claiming_halt_pc_does_not_reconcile() {
    let t = traced("fib", 24);
    let memory = memory_challenges();
    let log = prefix(&t);
    let last = *t.cycles.last().expect("a cycle");
    let mut shards = Vec::new();
    for (family, cycles) in frame_plan(&t) {
        let cycles: Vec<u64> = cycles.into_iter().filter(|c| *c < last).collect();
        if cycles.is_empty() {
            continue;
        }
        let height = frame_height(cycles.len());
        shards.push(frame_shard(&log, family, &cycles, height, &memory));
    }
    assert!(shards.len() > 1, "more than one family ran");
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
            // A RAM word's final value is a window family's row, and a
            // delegation space reports no final state at all.
            AddressSpace::Ram
            | AddressSpace::KeccakF
            | AddressSpace::Poseidon2
            | AddressSpace::FrArith => {}
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

/// Control C5, mask booleanity (`docs/spec/memory.md` §2.4). On the first
/// padding row of `ADD_SUB_LUI_AUIPC`'s frame, row 657, the pc query — slot 0 of
/// every frame — forged with mask −1: address 10, reading `x10`'s last write and
/// writing 42 at `4·2,118`, the row's cycle set to 2,118, one past fib's last,
/// with the boundary claiming `x10` ends at 42 there — the exit status. At
/// `m = −1` each of the query's two leaves is `−T(AS − 2, …)`: the pc query reads
/// and writes as a REG query, one sign flip on each side of the equation, so the
/// roots reconcile and every obligation holds. A single query's read and write
/// pair suffices; a second −1 query is not needed. `gkr::self_check` names
/// `pc_mask_boolean` on that row, the one gate that stops it; the same forgery
/// at mask 1, a PC query, does not reconcile.
///
/// Fails if the booleanity gate were missing — which the construction refuses,
/// `crates/constraints/tests/memory.rs`' `a_frame_missing_a_booleanity_gate_is_refused`.
#[test]
fn a_pc_query_masked_by_minus_1_reads_as_a_register_and_only_booleanity_refuses_it() {
    let f = fib();
    let row = f.plan[ALU].1.len();
    assert!(
        row < 1usize << f.shards[ALU].artifact.trace_vars,
        "a padding row"
    );
    let cycle = f.t.cycles.len() as u64 + 1;
    let ts = TS_STEP * cycle;
    let pc = slot(&f, ALU, PC).expect("every frame has the pc query");
    let (t10, v10) = (f.finals.reg_ts[10], f.finals.reg_values[9]);
    assert!(t10 < ts && ts - t10 - 1 < 1 << 19);
    let cells = |mask: Fr| {
        [
            (ALU, CYCLE, row, int(cycle)),
            (ALU, frame(pc, FIELD_MASK), row, mask),
            (ALU, frame(pc, FIELD_ADDR), row, int(10)),
            (ALU, frame(pc, FIELD_READ_TS), row, int(t10)),
            (ALU, frame(pc, FIELD_READ_VALUE), row, int(v10 as u64)),
            (ALU, frame(pc, FIELD_WRITE_VALUE), row, int(42)),
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
    let forged = tampered(&f.shards, &cells(Fr::MINUS_ONE));
    assert_eq!(surface(&f, &forged, &finals), expected);
    let as_pc = tampered(&f.shards, &cells(Fr::ONE));
    let expected = Surface {
        reconciles: false,
        ..honest()
    };
    assert_eq!(surface(&f, &as_pc, &finals), expected);
}

/// Control C6, why `MEMORY_BOUNDARY` precedes the squeeze
/// (`docs/spec/memory.md` §6.1) — a documentation test. Acceptance 2's
/// unbalanced statement, the first RAM store's read value moved in `MEM_WORD`'s
/// frame, with the challenges already drawn: `x10`'s final value solved as
/// `v = (T − γ_M − REG − α_addr·10 − α_ts·t_10)/α_val`, `T` being the tuple that
/// closes the equation. With `x10`'s boundary tuple at `v` the roots reconcile,
/// as they would for any trace; and `v` is not below `2^32`, so the verifier's
/// decoding of the boundary refuses it and `BoundaryFinals` cannot hold it. A
/// final value absorbed after the squeeze would have that range check alone
/// standing between a prover and this. Fails if the solved value were a `u32` —
/// about `2^32/p ≈ 2^−222` for a fresh draw; the draw here is fixed.
#[test]
fn a_final_value_solved_after_the_challenges_reconciles_and_is_not_a_u32() {
    let f = fib();
    let (i, row, at) = first_live(&f, RAM);
    let value = cell(&f.shards[i], frame(at, FIELD_READ_VALUE), row) + Fr::ONE;
    let unbalanced = tampered(&f.shards, &[(i, frame(at, FIELD_READ_VALUE), row, value)]);
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

/// Control C7, coverage rests on the gap obligation (`docs/spec/memory.md` §9).
/// On the first live row with no `ram` query, in a frame whose family has one, a
/// forged `ram` query at `0x4000_0000` — word 0 of window 4096, which fib's
/// statement does not list, so no row initializes or tears it down — reading its
/// own write: `read_ts = 4·cycle + Δ`, and 5 read and written. Its read tuple is
/// its write tuple, so the two cancel and the roots reconcile with every gate
/// holding; only the gap obligation names it, `gap_lo_ram` on that row, its gap
/// being −1. The same on the first live row with no `rs2` query, at register 32,
/// which no boundary tuple covers: only `gap_lo_rs2`. With `read_ts` one lower
/// neither is self-balancing, and neither reconciles. Each row is found in
/// whichever frame has the query and a row without it, so the two need not be
/// the same family's.
///
/// The cryptographic discharge of these obligations is S15's gate; until then
/// the native evaluator is the only check. Fails if the gap obligation admitted
/// a read of a query's own write.
#[test]
fn a_query_reading_its_own_write_balances_where_no_row_is_and_only_its_gap_catches_it() {
    let f = fib();
    for (q, addr, value) in [(RAM, 0x4000_0000, 5), (RS2, 32, 9)] {
        let (i, row, at) = first_empty(&f, q);
        assert_eq!(cell(&f.shards[i], gap_hi(at), row), Fr::ZERO);
        let cycle = small(cell(&f.shards[i], CYCLE, row));
        let ts = TS_STEP * cycle + FRAME_DELTA[q];
        let forgery = |read_ts: u64| {
            let cells = [
                (i, frame(at, FIELD_MASK), row, Fr::ONE),
                (i, frame(at, FIELD_ADDR), row, int(addr)),
                (i, frame(at, FIELD_READ_TS), row, int(read_ts)),
                (i, frame(at, FIELD_READ_VALUE), row, int(value)),
                (i, frame(at, FIELD_WRITE_VALUE), row, int(value)),
            ];
            surface(&f, &tampered(&f.shards, &cells), &f.finals)
        };
        let name = FRAME_NAMES[q];
        let expected = Surface {
            gate: Ok(()),
            lookups: vec![(row, format!("gap_lo_{name}"))],
            reconciles: true,
        };
        assert_eq!(forgery(ts), expected, "{name}");
        assert!(!forgery(ts - 1).reconciles, "{name}");
    }
}

/// Control C8, what S16's constraints owe the masks (`docs/spec/memory.md`
/// §2.1, §9) — a documentation test, and S16's tamper targets. Nothing at S14
/// ties a query's mask to its row's pc mask, or to the instruction the row looks
/// up, so each of these forgeries over fib keeps every gate and obligation and
/// reconciles:
///
/// 1. **a query on a row with no pc query**: the first padding row of
///    `ADD_SUB_LUI_AUIPC`'s frame, row 657, at cycle 2,118, pc mask 0 and `rd`
///    mask 1 — `rd` being slot 6 of that seven-query frame — reading `x10`'s last
///    write and writing 42, with `rd_inv = 1/10` and `rd_selected = 42` at
///    `W[7]` and `W[9]`, and the finals claiming `x10 = 42` — the exit status
///    rewritten after the exit row;
/// 2. **its reverse, a live row dropping a query**: fib's first two `rd` writes
///    in a row to one nonzero register, the first masked to 0 and the second
///    reading the write before it. The two are cycles of different families, so
///    the forgery spans `ADD_SUB_LUI_AUIPC`'s frame and `MEM_WORD`'s, `rd`
///    sitting at slot 6 of the one and slot 5 of the other;
/// 3. **a query a live row's instruction does not have**: the exit row, the last
///    cycle of `ADD_SUB_LUI_AUIPC`, which has no `ram` query, given one at slot 5
///    over the first stack word's last write, writing 99, and the stack window's
///    teardown there claiming it — a RAM word's final value that no instruction
///    wrote. Where a later instruction reads the word, the same forgery hands it
///    the 99.
///
/// S16 makes the pc mask the row's liveness and every other mask
/// `m_q = m_pc·uses_q`, with `uses_q` from the looked-up row kind; each of the
/// three must then be refused. Fails if an S14 check refused one.
#[test]
fn queries_their_row_does_not_have_reconcile_until_s16_couples_the_masks() {
    let f = fib();
    let hi = |ts: u64, read_ts: u64| int((ts - read_ts - 1) >> 19);
    let pc = slot(&f, ALU, PC).expect("every frame has the pc query");

    let row = f.plan[ALU].1.len();
    let cycle = f.t.cycles.len() as u64 + 1;
    let rd = slot(&f, ALU, RD).expect("every frame has rd");
    let ts = TS_STEP * cycle + FRAME_DELTA[RD];
    let (t10, v10) = (f.finals.reg_ts[10], f.finals.reg_values[9]);
    assert_eq!(cell(&f.shards[ALU], frame(pc, FIELD_MASK), row), Fr::ZERO);
    let w = width(&f, ALU);
    let cells = [
        (ALU, CYCLE, row, int(cycle)),
        (ALU, frame(rd, FIELD_MASK), row, Fr::ONE),
        (ALU, frame(rd, FIELD_ADDR), row, int(10)),
        (ALU, frame(rd, FIELD_READ_TS), row, int(t10)),
        (ALU, frame(rd, FIELD_READ_VALUE), row, int(v10 as u64)),
        (ALU, frame(rd, FIELD_WRITE_VALUE), row, int(42)),
        (ALU, gap_hi(rd), row, hi(ts, t10)),
        (ALU, rd_inv(w), row, int(10).inverse().expect("nonzero")),
        (ALU, rd_selected(w), row, int(42)),
    ];
    let mut finals = f.finals;
    (finals.reg_ts[10], finals.reg_values[9]) = (ts, 42);
    assert_eq!(surface(&f, &tampered(&f.shards, &cells), &finals), honest());

    let (w1, w2) = rd_writes_in_a_row(&f, |e| e.addr != 0);
    let (i1, r1, k1) = locate(&f, &w1);
    let (i2, r2, k2) = locate(&f, &w2);
    assert_eq!((i1, i2), (ALU, MEM), "the pair spans two families' frames");
    let cells = [
        (i1, frame(k1, FIELD_MASK), r1, Fr::ZERO),
        (i1, rd_inv(width(&f, i1)), r1, Fr::ZERO),
        (i2, frame(k2, FIELD_READ_TS), r2, int(w1.read_ts)),
        (
            i2,
            frame(k2, FIELD_READ_VALUE),
            r2,
            int(w1.read_value as u64),
        ),
        (i2, gap_hi(k2), r2, hi(w2.ts, w1.read_ts)),
    ];
    assert_eq!(
        surface(&f, &tampered(&f.shards, &cells), &f.finals),
        honest()
    );

    let last = *f.t.cycles.last().expect("a cycle");
    let (i, exit) = at_cycle(&f, last);
    let ram = slot(&f, i, RAM).expect("the exit row's family has a ram column");
    assert_eq!(i, ALU, "the exit row is an ecall");
    assert_eq!(cell(&f.shards[i], frame(pc, FIELD_MASK), exit), Fr::ONE);
    assert_eq!(cell(&f.shards[i], frame(ram, FIELD_MASK), exit), Fr::ZERO);
    let stack = |v: &&trace::FinalValue| {
        v.space == AddressSpace::Ram && v.addr / (4 * HEIGHT) == STACK_WINDOW
    };
    let finals = f.t.log.final_state();
    let word = finals.iter().find(stack).expect("a stack word");
    let ts = TS_STEP * last + FRAME_DELTA[RAM];
    let cells = [
        (i, frame(ram, FIELD_MASK), exit, Fr::ONE),
        (i, frame(ram, FIELD_ADDR), exit, int(word.addr as u64)),
        (i, frame(ram, FIELD_READ_TS), exit, int(word.ts)),
        (
            i,
            frame(ram, FIELD_READ_VALUE),
            exit,
            int(word.value as u64),
        ),
        (i, frame(ram, FIELD_WRITE_VALUE), exit, int(99)),
        (i, gap_hi(ram), exit, hi(ts, word.ts)),
    ];
    let mut forged = tampered(&f.shards, &cells);
    let y = window_row(word.addr, STACK_WINDOW);
    let teardown = [
        (PolyAddress::Memory(0), y, int(ts)),
        (PolyAddress::Memory(1), y, int(99)),
    ];
    forged[STACK] = with_cells(&f.shards[STACK], &teardown);
    assert_eq!(surface(&f, &forged, &f.finals), honest());
}
