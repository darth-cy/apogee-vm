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

use checker::{memory_roots, violated_lookups, violated_relations, WitnessRow};
use common::{
    cell, forwarded_shard, frame_plan, memory_challenges, shards, traced, with_cells, witness_row,
    Shard, Traced,
};
use constants::family;
use constants::memory::TS_STEP;
use constraints::memory::{
    family_frame_artifact, frame, frame_queries, gap_hi, rd_inv, rd_is_zero, rd_selected, CYCLE,
    FIELD_ADDR, FIELD_MASK, FIELD_READ_TS, FIELD_READ_VALUE, FIELD_WRITE_VALUE, FRAME_DELTA,
    FRAME_NAMES, FRAME_READ_ONLY, FRAME_SPACE, PC, RAM, RD, RS1,
};
use constraints::PolyAddress;
use field::Fr;
use gkr::{
    boundary_factors, reconciles, self_check, BoundaryFinals, ExternalChallenges, SelfCheckError,
};
use trace::{build_boundary_finals, AddressSpace, MemoryEvent};

/// fib's five frame shards, in `shards` order — the families that ran, ascending
/// — and then its two windows. `fib` pins the whole list.
const ALU: usize = 0;
const JUMP: usize = 1;
const MEM: usize = 3;
/// How many frames fib's statement has; the windows follow them.
const FRAMES: usize = 5;
fn int(v: u64) -> Fr {
    Fr::from_u64(v)
}

/// fib's honest statement: its trace, slots 1–4, its frame plan, its nine
/// shards — one frame per family that ran, then window 0 and the stack window,
/// then the two public value windows, in that order — and its finals.
///
/// The public windows are here because they are in **every** statement
/// (`docs/spec/public-values.md` §4). `fib` reads neither, so each window's
/// init and teardown tuples are equal and cancel, and every tamper below
/// reconciles or fails exactly as it did before they existed — which is the
/// point: they cost the memory argument nothing.
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
            "frame of mem_word",
            "frame of mem_subword",
            "window 0",
            "window 8191",
            "public input window 32",
            "public output",
        ]
    );
    let families: Vec<u32> = plan.iter().map(|(id, _)| *id).collect();
    assert_eq!(
        families,
        [
            family::ADD_SUB_LUI_AUIPC,
            family::JUMP_BRANCH_SLT,
            family::SHIFT_BITWISE,
            family::MEM_WORD,
            family::MEM_SUBWORD,
        ]
    );
    assert_eq!(plan.len(), FRAMES);
    let finals = build_boundary_finals(t.log.state());
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

/// `v`'s canonical integer, which fits a `u64`.
fn small(v: Fr) -> u64 {
    let b = v.to_bytes();
    assert!(b[8..].iter().all(|x| *x == 0), "{v:?} is past 64 bits");
    u64::from_le_bytes(b[..8].try_into().expect("8 bytes"))
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
