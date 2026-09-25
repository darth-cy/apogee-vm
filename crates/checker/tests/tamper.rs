//! S16's, S17's, S18's and S19's tamper twins, through `TamperHarness`: one
//! statement — `guests/addsub`, S17's `guests/control`, S18's `guests/alu` or
//! S19's `guests/mem` —
//! proved honestly once per test, then proved again with one tamper as an
//! honest prover would prove the tampered witness, and one shard verified
//! through `verify_shard`. Each twin asserts the class of the check that
//! refuses it (`docs/spec/shard-proof.md` §6).
//!
//! **`#[ignore]`d, and run by name with `--include-ignored --test-threads=1`**:
//! the add/sub shard is `2^20` rows and a statement's proof peaks at 8.6 GB —
//! 9.3 GB with the honest statement the harness holds beside a re-proof — and
//! `control`'s has two execution shards of that height, 11.3 GB. S18's `alu`
//! has four, and S19's `mem` five beside `INIT_TEARDOWN` and a `ZERO_WINDOWS`
//! shard — seven in all — which puts the file's peak at S19's statement.
//! The rows these tampers edit are `crates/checker/tests/add_sub.rs`'s, which
//! runs in ordinary CI.
//!
//! `addsub`'s rows are its 29 cycles in order: row 0 `lui t0`, row 4
//! `add t2, t0, t1` (carrying), row 5 `add t3, t1, t1`, row 8 `add x0, t0, t1`
//! (carrying, discarded), row 27 `addi a7, x0, 93`, row 28 the exit. Everything
//! from row 29 up is padding.
//!
//! S18 adds `guests/alu`, whose statement has four execution shards of `2^20`
//! rows — add/sub, jump/branch/slt, shift/bitwise and mul/div. Its twins name
//! no row number: the shift and mul/div rows are found by their committed kind
//! bit and by the very cell the twin corrupts, so a guest that grows a check
//! keeps the test honest. The rows themselves, instruction by instruction, are
//! `crates/checker/tests/shift_bitwise.rs`' and `crates/checker/tests/
//! mul_div.rs`', which run in ordinary CI.
//!
//! S19 adds `guests/mem`, whose statement is **the largest in the file**: five
//! execution shards of `2^20` rows — those two, plus `MEM_WORD`, `MEM_SUBWORD`
//! and `ATOMICS` — beside `INIT_TEARDOWN` and the first `ZERO_WINDOWS` shard
//! any acceptance statement has had. Its twins find their rows the same way,
//! and the rows are `crates/checker/tests/mem_word.rs`', `mem_subword.rs`' and
//! `atomics.rs`', in ordinary CI.

#[path = "../../prover/tests/common/mod.rs"]
mod common;

use checker::{Cell, Tamper, TamperHarness};
use constants::extra_mask::jump_branch_slt as kind;
use constants::extra_mask::mul_div as md_kind;
use constants::extra_mask::shift_bitwise as sb_kind;
use constants::family::JUMP_BRANCH_SLT as JBS;
use constants::family::{ADD_SUB_LUI_AUIPC as ADD, INIT_TEARDOWN as INIT};
use constants::family::{MUL_DIV as MD, SHIFT_BITWISE as SHB};
use constants::lookup_channel;
use constraints::add_sub::{DECODED, KINDS, MULTIPLICITIES, NEXT_PC_HI, PC_WRAP, RD_HI, WRAP};
use constraints::jump_branch_slt as jbs;
use constraints::memory::{
    frame, gap_hi, rd_inv, rd_is_zero, rd_selected, CYCLE, FIELD_ADDR, FIELD_MASK, FIELD_READ_TS,
    FIELD_READ_VALUE, FIELD_WRITE_VALUE,
};
use constraints::mul_div as md;
use constraints::shift_bitwise as sb;
use constraints::PolyAddress;
use field::Fr;
use prover::{shard_columns, ProverSetup};
use trace::{build_multiplicities, Role, TraceArchive};
use verifier::VerifyError;

/// `ADD_SUB_LUI_AUIPC`'s frame width, and the **slot** of each query this file
/// touches — a position in `frame_queries(ADD)`, never a query id.
///
/// S21 appended `deleg`, so the width is 8 and `rd`'s slot is still 6; a query
/// inserted rather than appended would move every one of these silently, which
/// is what `the_slot_constants_are_the_frames` below exists to catch. It runs
/// in ordinary CI, unlike every proof test in this file.
const WIDTH: usize = 8;
const PC: usize = 0;
const RS1: usize = 1;
const RS2: usize = 2;
const RAM: usize = 5;
const RD: usize = 6;
const DELEG: usize = 7;

/// The slot constants above against the frozen frame, and the witness columns
/// they index against the circuit's own names. No proof, so this is the one
/// test in this file CI runs.
#[test]
fn the_slot_constants_are_the_frames() {
    let queries = constraints::memory::frame_queries(ADD);
    assert_eq!(queries.len(), WIDTH, "the add/sub frame is {WIDTH} queries");
    use constraints::memory as m;
    for (slot, id) in [
        (PC, m::PC),
        (RS1, m::RS1),
        (RS2, m::RS2),
        (RAM, m::RAM),
        (RD, m::RD),
        (DELEG, m::DELEG),
    ] {
        assert_eq!(queries[slot], id, "slot {slot}");
    }
    // And the x0 gadget's three columns, which follow the frame's gap chunks.
    let a = &constraints::family_circuit(ADD, 20)
        .expect("the add/sub circuit")
        .artifact;
    let name = |address: PolyAddress| match address {
        PolyAddress::Witness(i) => a.witness[i as usize].clone(),
        other => panic!("{other} is not a witness column"),
    };
    assert_eq!(name(rd_inv(WIDTH)), "rd_inv");
    assert_eq!(name(rd_is_zero(WIDTH)), "rd_is_zero");
    assert_eq!(name(rd_selected(WIDTH)), "rd_selected");
    assert_eq!(name(gap_hi(DELEG)), "deleg_gap_hi");
}

const CONSTRAINT: VerifyError = VerifyError::Constraint { layer: 0 };
const MEMORY: VerifyError = VerifyError::MemoryArgument("");
const OPENING: VerifyError = VerifyError::Opening;

fn lookup(channel: u32) -> VerifyError {
    VerifyError::Lookup { channel }
}

fn f(v: u64) -> Fr {
    Fr::from_u64(v)
}

fn cell(family: u32, address: PolyAddress, row: usize, value: Fr) -> Cell {
    Cell {
        family,
        shard: 0,
        address,
        row,
        value,
    }
}

fn tamper(cells: Vec<Cell>) -> Tamper {
    Tamper {
        cells,
        boundary: None,
    }
}

/// The first row of RAM window 0: the word at `RAM_ORIGIN`, `addsub`'s first
/// instruction, which no row reads or writes.
const IMAGE_ROW: usize = 1 << 14;

/// Acceptance 2, 3 and 4 — the stage gate, three distinct classes on screen:
/// a semantics cell, `Constraint`; a memory event's value and its timestamp,
/// `MemoryArgument`; a lookup multiplicity, `Lookup`.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 8.6 GB"]
fn a2_a3_a4_a_semantics_a_memory_and_a_multiplicity_cell_fail_in_three_classes() {
    let setup = common::setup();
    let archive = common::archive(&setup.program);
    let h = TamperHarness::new(&setup, &archive);

    // 2. The carrying add's wrap bit, cleared; and the non-carrying add's
    //    computed value moved.
    assert_eq!(h.cell(ADD, 0, WRAP, 4), Fr::ONE);
    h.assert_rejects(
        &tamper(vec![cell(ADD, WRAP, 4, Fr::ZERO)]),
        (ADD, 0),
        CONSTRAINT,
    );
    let sel = h.cell(ADD, 0, rd_selected(WIDTH), 5);
    h.assert_rejects(
        &tamper(vec![cell(ADD, rd_selected(WIDTH), 5, sel + Fr::ONE)]),
        (ADD, 0),
        CONSTRAINT,
    );

    // 3. A teardown value no gate reads, and a pc read's timestamp one lower —
    //    its gap chunk still in range and its multiplicity recounted — both
    //    pinned by the multiset alone.
    let word = h.cell(INIT, 0, PolyAddress::Memory(1), IMAGE_ROW);
    h.assert_rejects(
        &tamper(vec![cell(
            INIT,
            PolyAddress::Memory(1),
            IMAGE_ROW,
            word + Fr::ONE,
        )]),
        (INIT, 0),
        MEMORY,
    );
    let read_ts = frame(PC, FIELD_READ_TS);
    assert_eq!(h.cell(ADD, 0, read_ts, 3), f(12));
    h.assert_rejects(
        &tamper(vec![cell(ADD, read_ts, 3, f(11))]),
        (ADD, 0),
        MEMORY,
    );

    // 4. One multiplicity cell, in the range channel and in the decoder's.
    let m = h.cell(ADD, 0, MULTIPLICITIES[1], 0);
    h.assert_rejects(
        &tamper(vec![cell(ADD, MULTIPLICITIES[1], 0, m + Fr::ONE)]),
        (ADD, 0),
        lookup(lookup_channel::RANGE16),
    );
    let first = 0x1_0000 / 2;
    let m = h.cell(ADD, 0, MULTIPLICITIES[2], first);
    assert_eq!(m, Fr::ONE, "the first instruction runs once");
    h.assert_rejects(
        &tamper(vec![cell(ADD, MULTIPLICITIES[2], first, Fr::ZERO)]),
        (ADD, 0),
        lookup(lookup_channel::DECODER),
    );
}

/// Acceptance 7, the soundness floor. An unreduced sum is refused by the range
/// channel; a wrap of 2 by its booleanity; an all-zero family mask by the
/// decoder channel's domain, every gate and range still holding; a `next_pc`
/// outside 32 bits by the range channel.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 8.6 GB"]
fn a7_the_soundness_floor_refuses_each_of_its_controls() {
    let setup = common::setup();
    let archive = common::archive(&setup.program);
    let h = TamperHarness::new(&setup, &archive);
    let sel = rd_selected(WIDTH);

    // Row 8, `add x0, t0, t1`: its rd write is 0 whatever it computes, so
    // these tampers reach no memory event.
    let a = h.cell(ADD, 0, frame(RS1, FIELD_READ_VALUE), 8);
    let b = h.cell(ADD, 0, frame(RS2, FIELD_READ_VALUE), 8);
    let (a, b) = (small(a), small(b));
    assert_eq!(h.cell(ADD, 0, frame(RD, FIELD_ADDR), 8), Fr::ZERO);
    assert!(a + b >= 1 << 32, "the sum carries");
    h.assert_rejects(
        &tamper(vec![
            cell(ADD, WRAP, 8, Fr::ZERO),
            cell(ADD, sel, 8, f(a + b)),
            cell(ADD, RD_HI, 8, f((a + b) >> 16)),
        ]),
        (ADD, 0),
        lookup(lookup_channel::RANGE16),
    );
    h.assert_rejects(
        &tamper(vec![
            cell(ADD, WRAP, 8, f(2)),
            cell(ADD, sel, 8, f(a + b) - f(1 << 33)),
            cell(ADD, RD_HI, 8, Fr::ZERO),
        ]),
        (ADD, 0),
        CONSTRAINT,
    );

    // Row 0, `lui t0`: its mask and its one bit cleared, and its rd query
    // dropped to match, so every gate still holds.
    let mut zero = vec![
        cell(ADD, DECODED[5], 0, Fr::ZERO),
        cell(ADD, KINDS[5], 0, Fr::ZERO),
        cell(ADD, rd_inv(WIDTH), 0, Fr::ZERO),
        cell(ADD, rd_is_zero(WIDTH), 0, Fr::ZERO),
        cell(ADD, sel, 0, Fr::ZERO),
        cell(ADD, RD_HI, 0, Fr::ZERO),
        cell(ADD, gap_hi(RD), 0, Fr::ZERO),
    ];
    for field in [
        FIELD_MASK,
        FIELD_ADDR,
        FIELD_READ_TS,
        FIELD_READ_VALUE,
        FIELD_WRITE_VALUE,
    ] {
        zero.push(cell(ADD, frame(RD, field), 0, Fr::ZERO));
    }
    h.assert_rejects(&tamper(zero), (ADD, 0), lookup(lookup_channel::DECODER));

    // Row 4: next_pc − 2^32 with a wrap of 1.
    let next = h.cell(ADD, 0, DECODED[0], 4);
    h.assert_rejects(
        &tamper(vec![
            cell(ADD, PC_WRAP, 4, Fr::ONE),
            cell(ADD, frame(PC, FIELD_WRITE_VALUE), 4, next - f(1 << 32)),
            cell(ADD, NEXT_PC_HI, 4, Fr::ZERO),
        ]),
        (ADD, 0),
        lookup(lookup_channel::RANGE16),
    );
}

/// Acceptance 11, the harness's negative control: cells nothing reads — a
/// padding row's gap chunk, whose obligation its mask switches off, and a
/// padding row's `rd_inv`, which multiplies an address of 0 — change and the
/// statement still verifies. The harness tells a harmless edit from a harmful
/// one.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 8.6 GB"]
fn a11_a_cell_nothing_reads_still_verifies() {
    let setup = common::setup();
    let archive = common::archive(&setup.program);
    let h = TamperHarness::new(&setup, &archive);
    h.assert_verifies(&tamper(vec![cell(ADD, gap_hi(PC), 100, f(5))]), (ADD, 0));
    h.assert_verifies(
        &tamper(vec![cell(ADD, rd_inv(WIDTH), 1000, f(7))]),
        (ADD, 0),
    );
    // The other shard sees the same statement, and verifies too.
    h.assert_verifies(&tamper(vec![cell(ADD, gap_hi(PC), 100, f(5))]), (INIT, 0));
}

/// Acceptance 13, as the owner remapped it: the committed result is the exit
/// status, `x10`'s final value, and the teardown is what binds final values.
/// A RAM teardown value or timestamp changed, and `x10`'s final value changed
/// while the public exit status stays honest, are each refused as
/// `MemoryArgument` — on both shards.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 8.6 GB"]
fn a13_the_teardown_binds_the_final_values() {
    let setup = common::setup();
    let archive = common::archive(&setup.program);
    let h = TamperHarness::new(&setup, &archive);
    let row = IMAGE_ROW + 5;
    let value = h.cell(INIT, 0, PolyAddress::Memory(1), row);
    let moved = tamper(vec![cell(
        INIT,
        PolyAddress::Memory(1),
        row,
        value + Fr::ONE,
    )]);
    h.assert_rejects(&moved, (INIT, 0), MEMORY);
    h.assert_rejects(&moved, (ADD, 0), MEMORY);
    let stamped = tamper(vec![cell(
        INIT,
        PolyAddress::Memory(0),
        IMAGE_ROW + 3,
        f(5),
    )]);
    h.assert_rejects(&stamped, (INIT, 0), MEMORY);
    h.assert_rejects(&stamped, (ADD, 0), MEMORY);
    let (public, _) = h.honest();
    // A boundary timestamp past the clock, proved under: step 10 refuses it
    // before reconciliation. Only an in-memory statement can carry one;
    // `PublicInputs::from_bytes` refuses it first.
    let mut late = public.boundary;
    late.reg_ts[5] = 1 << 38;
    let late = Tamper {
        cells: vec![],
        boundary: Some(late),
    };
    assert_eq!(
        h.run(&late, (ADD, 0)),
        Err(VerifyError::MemoryArgument(
            "a boundary timestamp is not below 2^38"
        ))
    );
    let mut finals = public.boundary;
    assert_eq!(finals.reg_values[9], common::RESULT);
    finals.reg_values[9] = common::RESULT + 1;
    let result = Tamper {
        cells: vec![],
        boundary: Some(finals),
    };
    assert_eq!(
        h.run(&result, (ADD, 0)),
        Err(VerifyError::MemoryArgument(
            "x10's final value is not the exit status"
        ))
    );
    h.assert_rejects(&result, (INIT, 0), MEMORY);
}

/// The tamper targets S14 left to S16, `docs/spec/memory.md` §2.1 and §5, and
/// the image column's opening, §6.2: each refused.
///
/// - control C8's three forgeries: a padding row's `rd` query rewriting `x10`
///   after the exit, a live row's `rd` write masked off, and the exit row
///   given a store — each `Constraint`;
/// - the exit rewriting its status — `Constraint`;
/// - a row that is not the exit writing `HALT_PC`, the truncation target —
///   `Constraint`;
/// - the image column and a teardown value moved together, so the multiset
///   still balances — refused by the opening of `S[0]` against the identity's
///   commitment, `Opening`.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 8.6 GB"]
fn the_targets_s14_left_to_s16_are_refused() {
    let setup = common::setup();
    let archive = common::archive(&setup.program);
    let h = TamperHarness::new(&setup, &archive);
    let sel = rd_selected(WIDTH);

    // C8, first: a padding row, cycle 30, rewriting x10 from 42 to 43.
    let (public, _) = h.honest();
    let x10_ts = public.boundary.reg_ts[10];
    let mut forgery = vec![
        cell(ADD, CYCLE, 100, f(30)),
        cell(ADD, frame(RD, FIELD_MASK), 100, Fr::ONE),
        cell(ADD, frame(RD, FIELD_ADDR), 100, f(10)),
        cell(ADD, frame(RD, FIELD_READ_TS), 100, f(x10_ts)),
        cell(ADD, frame(RD, FIELD_READ_VALUE), 100, f(42)),
        cell(ADD, frame(RD, FIELD_WRITE_VALUE), 100, f(43)),
        cell(ADD, rd_inv(WIDTH), 100, f(10).inverse().unwrap()),
        cell(ADD, sel, 100, f(43)),
    ];
    let mut finals = public.boundary;
    finals.reg_ts[10] = 4 * 30 + 3;
    finals.reg_values[9] = 43;
    let c8 = Tamper {
        cells: forgery.clone(),
        boundary: Some(finals),
    };
    h.assert_rejects(&c8, (ADD, 0), CONSTRAINT);
    forgery.clear();

    // C8, second: row 5's rd write masked off.
    for field in [
        FIELD_MASK,
        FIELD_ADDR,
        FIELD_READ_TS,
        FIELD_READ_VALUE,
        FIELD_WRITE_VALUE,
    ] {
        forgery.push(cell(ADD, frame(RD, field), 5, Fr::ZERO));
    }
    forgery.push(cell(ADD, rd_inv(WIDTH), 5, Fr::ZERO));
    forgery.push(cell(ADD, gap_hi(RD), 5, Fr::ZERO));
    h.assert_rejects(&tamper(forgery), (ADD, 0), CONSTRAINT);

    // C8, third: the exit row storing 7 into the top stack word, never
    // written before.
    let store = vec![
        cell(ADD, frame(RAM, FIELD_MASK), 28, Fr::ONE),
        cell(ADD, frame(RAM, FIELD_ADDR), 28, f(0x7fff_fffc)),
        cell(ADD, frame(RAM, FIELD_WRITE_VALUE), 28, f(7)),
    ];
    h.assert_rejects(&tamper(store), (ADD, 0), CONSTRAINT);

    // The exit rewriting a0.
    h.assert_rejects(
        &tamper(vec![
            cell(ADD, frame(RD, FIELD_WRITE_VALUE), 28, f(43)),
            cell(ADD, sel, 28, f(43)),
        ]),
        (ADD, 0),
        CONSTRAINT,
    );

    // Row 27, `addi a7, x0, 93`, writing HALT_PC.
    h.assert_rejects(
        &tamper(vec![
            cell(ADD, frame(PC, FIELD_WRITE_VALUE), 27, Fr::ONE),
            cell(ADD, NEXT_PC_HI, 27, Fr::ZERO),
        ]),
        (ADD, 0),
        CONSTRAINT,
    );

    // The image column and the teardown of one untouched word, moved together.
    let row = IMAGE_ROW + 10;
    let word = h.cell(INIT, 0, PolyAddress::Setup(0), row);
    assert_eq!(word, h.cell(INIT, 0, PolyAddress::Memory(1), row));
    h.assert_rejects(
        &tamper(vec![
            cell(INIT, PolyAddress::Setup(0), row, word + Fr::ONE),
            cell(INIT, PolyAddress::Memory(1), row, word + Fr::ONE),
        ]),
        (INIT, 0),
        OPENING,
    );
}

/// A field element's canonical integer, which the tests only read where it is
/// a `u32`.
fn small(v: Fr) -> u64 {
    let b = v.to_bytes();
    assert!(b[4..].iter().all(|x| *x == 0), "{v:?} is not a u32");
    u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64
}

// ---------------------------------------------------------------------------
// S17: the jump/branch/slt family, over `guests/control`
// ---------------------------------------------------------------------------

/// `control`'s frame: pc, rs1, rs2, rd at slots 0 to 3.
const JBS_RS1: usize = 1;
const JBS_RD: usize = 3;

/// The index, in `control`'s jump/branch/slt buffer — its one shard's rows —
/// of the first row whose kind bit and trace row `pick` accepts.
fn jbs_row(
    setup: &ProverSetup,
    archive: &TraceArchive,
    pick: fn(u32, &trace::Row) -> bool,
) -> usize {
    let table = setup
        .program
        .tables
        .family(JBS)
        .expect("the family's table");
    let traces = archive.family_traces();
    let buffer = traces.family(JBS).expect("the family's buffer");
    (0..buffer.len())
        .find(|&i| {
            let row = buffer.row(i);
            let mask = table.get(6, row.pc as usize / 2).expect("a live row");
            pick(mask.trailing_zeros(), &row)
        })
        .expect("control runs the row the test names")
}

fn jbs_cell(address: PolyAddress, row: usize, value: Fr) -> Cell {
    cell(JBS, address, row, value)
}

/// S17 acceptance 7, and the generic channel's two bindings. The honest,
/// branch-heavy statement verifies (the harness asserts it); then, each
/// refused in its class:
///
/// - one corrupted `lt` cell, from `BLT(1, 0x80000000)`, which is not taken:
///   the comparison and the branch form refuse it, `Constraint`;
/// - the same forgery carried through — `lt`, the gap moved by `2^32` and its
///   high halfword with it, `taken` and the pc written at the branch's
///   target — which every gate accepts: the gap's range check is what refuses
///   it, `Lookup { RANGE16 }`;
/// - the written `next_pc` of the `jalr`, moved two bytes on together with
///   the `rs1` it is formed from, every gate and bound still holding: only the
///   global memory argument refuses it, `MemoryArgument` — and again with the
///   add/sub row that wrote that `rs1` moved to match, so the register's chain
///   balances and the pc's alone does not;
/// - one generic-channel count moved, `Lookup { GENERIC }`;
/// - a packed-table cell no row looks up, poisoned — `37 AND 45` answering 0
///   — which no gate and no channel sees: the opening of the table's columns
///   against the key's commitments refuses it, `Opening`.
///
/// And two cells nothing reads, on a padding row, still verify.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks near 10 GB"]
fn s17_a7_the_comparison_and_the_pc_are_pinned() {
    let setup = common::control_setup();
    let archive = common::control_archive(&setup.program);
    let h = TamperHarness::new(&setup, &archive);
    let columns = shard_columns(&setup, &archive, JBS, 0, &[]).expect("the honest shard");
    let at = |address: PolyAddress, row: usize| {
        columns
            .iter()
            .find(|(a, _)| *a == address)
            .unwrap_or_else(|| panic!("no {address}"))
            .1
            .get(row)
    };

    // BLT(1, 0x80000000): not taken.
    let r = jbs_row(&setup, &archive, |bit, row| {
        bit == kind::BLT
            && row.query(Role::Rs1).map(|q| q.read_value) == Some(1)
            && row.query(Role::Rs2).map(|q| q.read_value) == Some(0x8000_0000)
    });
    assert_eq!(at(jbs::LT, r), Fr::ZERO);
    assert_eq!(at(jbs::TAKEN, r), Fr::ZERO);
    h.assert_rejects(
        &tamper(vec![jbs_cell(jbs::LT, r, Fr::ONE)]),
        (JBS, 0),
        CONSTRAINT,
    );
    let (pc, imm) = (
        small(at(frame(PC, FIELD_READ_VALUE), r)),
        small(at(jbs::DECODED[4], r)),
    );
    let target = (pc + imm) & 0xffff_ffff;
    let gap = at(jbs::CMP_GAP, r) + f(1 << 32);
    let gap_hi = at(jbs::CMP_GAP_HI, r) + f(1 << 16);
    h.assert_rejects(
        &tamper(vec![
            jbs_cell(jbs::LT, r, Fr::ONE),
            jbs_cell(jbs::CMP_GAP, r, gap),
            jbs_cell(jbs::CMP_GAP_HI, r, gap_hi),
            jbs_cell(jbs::TAKEN, r, Fr::ONE),
            jbs_cell(frame(PC, FIELD_WRITE_VALUE), r, f(target)),
            jbs_cell(jbs::NEXT_PC_HI, r, f(target >> 16)),
        ]),
        (JBS, 0),
        lookup(lookup_channel::RANGE16),
    );

    // The jalr: rs1 = rd, imm = -2, bit 0 of rs1 + imm set.
    let r = jalr_row(&setup, &archive);
    let v = small(at(frame(JBS_RS1, FIELD_READ_VALUE), r));
    let next = small(at(frame(PC, FIELD_WRITE_VALUE), r));
    assert_eq!(at(jbs::JALR_DROP, r), Fr::ONE);
    assert_eq!(next, (v - 2) & !1);
    h.assert_rejects(&tamper(jalr_moved(r, v, next)), (JBS, 0), MEMORY);
    // `addi t2, t2, 3`, the add/sub row just before the jalr, wrote `v`. Its
    // write moved too, the register's read and write pair up again, and the
    // pc's is the one imbalance left. The add/sub shard is re-proved over its
    // broken gate, and only this family's shard is verified.
    let jalr_pc = small(at(frame(PC, FIELD_READ_VALUE), r)) as u32;
    let traces = archive.family_traces();
    let adds = traces.family(ADD).expect("the add/sub buffer");
    let a = (0..adds.len())
        .find(|&i| {
            let row = adds.row(i);
            row.next_pc == jalr_pc && row.query(Role::Rd).map(|q| q.write_value as u64) == Some(v)
        })
        .expect("the add/sub row writing the jalr's rs1");
    let mut pc_only = jalr_moved(r, v, next);
    pc_only.push(cell(ADD, frame(RD, FIELD_WRITE_VALUE), a, f(v + 2)));
    h.assert_rejects(&tamper(pc_only), (JBS, 0), MEMORY);

    // The generic channel's count of the ZeroEntry, and a poisoned AND row.
    let m = at(jbs::MULTIPLICITIES[2], 0);
    h.assert_rejects(
        &tamper(vec![jbs_cell(jbs::MULTIPLICITIES[2], 0, m + Fr::ONE)]),
        (JBS, 0),
        lookup(lookup_channel::GENERIC),
    );
    let and_row = 1 + 37 * 256 + 45;
    assert_eq!(at(jbs::GENERIC_TABLE[0], and_row), f(37 + 1));
    assert_eq!(at(jbs::GENERIC_TABLE[2], and_row), f(37 & 45));
    assert_eq!(at(jbs::MULTIPLICITIES[2], and_row), Fr::ZERO);
    h.assert_rejects(
        &tamper(vec![jbs_cell(jbs::GENERIC_TABLE[2], and_row, Fr::ZERO)]),
        (JBS, 0),
        OPENING,
    );

    // A padding row's dropped bit and its equality inverse: nothing reads
    // either where every mask and kind bit is 0.
    let padding = 1000;
    assert_eq!(at(frame(PC, FIELD_MASK), padding), Fr::ZERO);
    h.assert_verifies(
        &tamper(vec![
            jbs_cell(jbs::JALR_DROP, padding, Fr::ONE),
            jbs_cell(jbs::EQ_INV, padding, f(7)),
        ]),
        (JBS, 0),
    );
}

/// `control`'s `jalr t2, -2(t2)`: `rs1` and `rd` the one register, its
/// immediate `-2`.
fn jalr_row(setup: &ProverSetup, archive: &TraceArchive) -> usize {
    jbs_row(setup, archive, |bit, row| {
        let (rs1, rd) = (row.query(Role::Rs1), row.query(Role::Rd));
        bit == kind::JALR && rs1.is_some() && rs1.map(|q| q.addr) == rd.map(|q| q.addr)
    })
}

/// The `jalr` at row `r`, reading `v` and landing at `next`, re-run on
/// `v + 2`: its `rs1` read and write-back, its `rd` read — the same register,
/// written at slot 1 — the pc it writes, and what the comparison and the
/// equality gadget computed from `rs1`. Bit 0 and the wrap are unchanged, so
/// every gate and every bound holds; the register's chain and the pc's do not.
fn jalr_moved(r: usize, v: u64, next: u64) -> Vec<Cell> {
    let moved = v + 2;
    vec![
        jbs_cell(frame(JBS_RS1, FIELD_READ_VALUE), r, f(moved)),
        jbs_cell(frame(JBS_RS1, FIELD_WRITE_VALUE), r, f(moved)),
        jbs_cell(frame(JBS_RD, FIELD_READ_VALUE), r, f(moved)),
        jbs_cell(frame(PC, FIELD_WRITE_VALUE), r, f(next + 2)),
        jbs_cell(jbs::EQ_INV, r, f(moved).inverse().unwrap()),
        jbs_cell(jbs::CMP_GAP, r, f(moved)),
    ]
}

/// S17 acceptance 6, fetch binding. The `jalr` above re-run two bytes further
/// lands in the middle of the 32-bit `sltiu` it jumps to — the second
/// halfword, which no family's table holds — and the row after it is moved
/// there with it, so the pc's chain is whole. Every gate still holds; the
/// honest prover's recount of the decoder channel fails loudly, naming the
/// channel, because the table's row there is its `MINUS_ONE` padding; and the
/// proof it makes anyway is refused by that channel, `Lookup { DECODER }`,
/// before the memory argument sees the moved register.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks near 10 GB"]
fn s17_a6_a_jump_to_a_pc_holding_no_instruction_is_unprovable() {
    let setup = common::control_setup();
    let archive = common::control_archive(&setup.program);
    let h = TamperHarness::new(&setup, &archive);
    let mut columns = shard_columns(&setup, &archive, JBS, 0, &[]).expect("the honest shard");
    let at = |columns: &[(PolyAddress, poly::MultilinearPoly)], address: PolyAddress, row| {
        columns
            .iter()
            .find(|(a, _)| *a == address)
            .unwrap_or_else(|| panic!("no {address}"))
            .1
            .get(row)
    };

    let r = jalr_row(&setup, &archive);
    let v = small(at(&columns, frame(JBS_RS1, FIELD_READ_VALUE), r));
    let next = small(at(&columns, frame(PC, FIELD_WRITE_VALUE), r));
    // The jalr lands on this family's next row, a 32-bit instruction whose
    // second halfword no family's table holds.
    assert_eq!(
        small(at(&columns, frame(PC, FIELD_READ_VALUE), r + 1)),
        next
    );
    let tables = &setup.program.tables;
    assert!(tables.family(JBS).unwrap().is_live(next as usize / 2));
    for table in &tables.families {
        assert!(
            !table.is_live(next as usize / 2 + 1),
            "family {} holds pc {:#x}",
            table.family,
            next + 2
        );
    }

    let mut cells = jalr_moved(r, v, next);
    cells.push(jbs_cell(frame(PC, FIELD_READ_VALUE), r + 1, f(next + 2)));

    // The honest prover cannot count the decoder channel over it.
    for c in &cells {
        let column = columns
            .iter_mut()
            .find(|(a, _)| *a == c.address)
            .expect("a committed column");
        let mut values: Vec<Fr> = (0..column.1.len()).map(|i| column.1.get(i)).collect();
        values[c.row] = c.value;
        column.1 = poly::MultilinearPoly::new(poly::PolyBacking::Fr(values));
    }
    let circuit = setup.vk.circuit(JBS).expect("the family's circuit");
    let decoder = circuit
        .channels
        .iter()
        .find(|spec| spec.channel == lookup_channel::DECODER)
        .expect("the decoder channel");
    let refusal = build_multiplicities(&circuit.artifact, &columns, std::slice::from_ref(decoder))
        .expect_err("a row at a pc no table holds cannot be counted");
    assert!(refusal.contains("channel `decoder`"), "{refusal}");

    h.assert_rejects(&tamper(cells), (JBS, 0), lookup(lookup_channel::DECODER));
}

// ---------------------------------------------------------------------------
// S18: the shift/bitwise and mul/div families, over `guests/alu`
// ---------------------------------------------------------------------------

/// The row the negative control edits, and the bound of the scan that finds
/// the rows the twins corrupt. Both S18 families run well under a hundred live
/// rows of `alu`, and every row above them is padding, whose committed cells
/// are all zero — so this row is padding, and a predicate that reads a nonzero
/// cell cannot match on any padding row below it.
const ALU_PADDING: usize = 1000;

/// The value `address` holds at `row` of one shard's committed columns.
fn at(columns: &[(PolyAddress, poly::MultilinearPoly)], address: PolyAddress, row: usize) -> Fr {
    columns
        .iter()
        .find(|(a, _)| *a == address)
        .unwrap_or_else(|| panic!("no {address}"))
        .1
        .get(row)
}

/// The first row of `columns` carrying kind bit `bit` on which `cell` is not
/// zero: the row a twin corrupts, found by the very cell it corrupts, so no
/// twin here names a row number.
fn alu_row(
    columns: &[(PolyAddress, poly::MultilinearPoly)],
    bit: PolyAddress,
    cell: PolyAddress,
    what: &str,
) -> usize {
    (0..ALU_PADDING)
        .find(|&i| at(columns, bit, i) == Fr::ONE && at(columns, cell, i) != Fr::ZERO)
        .unwrap_or_else(|| panic!("alu runs no {what}"))
}

/// S18 acceptance 8, one twin per family and three refusal classes on screen.
/// The honest `alu` statement — four execution shards of `2^20` rows, the
/// largest in this file — verifies (the harness asserts it); its structural
/// counts are the two documents'; and then, each refused in its class:
///
/// - **the residue twin.** One `residue` cell of an `sra` that discards a bit,
///   raised by one. `residue` is what a right shift's floor-division identity
///   `rs1 − 2^32·se = (rd − 2^32·se)·2^s + residue` balances with, and
///   `scaled = residue·2^(32 − s)` is the copower half of its bound, so the
///   circuit refuses it: `Constraint`. This is the stage's named
///   shift/bitwise twin.
/// - **the product-high twin.** One `p_high` cell of a `mulh` whose product has
///   a high half, raised by one. The one product identity
///   `mx·my = p_low + 2^32·p_high − 2^64·p_sign` covers all four multiplies and
///   the division alike, and `rd` is `p_high` on this row, so two gates refuse
///   it: `Constraint`. This is the stage's named mul/div twin.
/// - **a multiplicity, in a second class.** The shift family's `GENERIC` count
///   of the `ZeroEntry`, the packed table's first row, which every switched-off
///   lookup of the shard gates to, raised by one. Every gate still holds and
///   every range is still in range; the channel whose count it is —
///   the one carrying `U16GetSign`, the shift powers and the four AND bytes —
///   is what refuses it, `Lookup { GENERIC }`, and the harness's per-channel
///   recount leaves that column alone precisely because it is the tamper.
/// - **a memory column, in a third class.** The pc read timestamp of a live
///   mul/div row, lowered by one. Its gap chunk stays in range and its
///   multiplicity is recounted, the shard's memory columns are recommitted,
///   and the tuple then matches no write in the statement: only the global
///   multiset refuses it, `MemoryArgument`.
///
/// And the negative control, which is what says the four above mean anything:
/// cells nothing reads, on a padding row of each family, change and the
/// statement still verifies. On the shift family's, `pow` — whose one product
/// `pow·copow` has a copower of 0 there, whose `shift_prod` product has a
/// `shift_in` of 0, and whose `ShiftPowers` lookup `f_shift` switches off — and
/// one AND byte, which no gate reads but through a kind bit and no lookup but
/// under `f_bitwise`. On the mul/div family's, the two is-zero inverses, which
/// multiply `r` and `rs2`, both 0 there. None of the four is range checked.
#[test]
#[ignore = "four 2^20-row execution shards, and the honest statement beside a re-proof: 15.7 GB"]
fn s18_a8_the_residue_and_the_product_high_are_pinned() {
    let setup = common::alu_setup();
    let archive = common::alu_archive(&setup.program);
    let h = TamperHarness::new(&setup, &archive);

    // The structural counts: seven shards, `ZERO_WINDOWS` and `ADVICE_WINDOWS`
    // the two families of the config that do not run, and each new family's
    // committed width — `docs/spec/shift-bitwise.md` §6 and
    // `docs/spec/mul-div.md` §6. The two public value families prove one shard
    // each whatever the program does (`docs/spec/public-values.md` §4).
    let (public, proofs) = h.honest();
    assert_eq!(public.shard_counts, vec![1, 1, 1, 1, 1, 0, 1, 1, 0]);
    let shards: Vec<(u32, u32)> = proofs.iter().map(|p| (p.family, p.shard_index)).collect();
    assert_eq!(
        shards,
        vec![
            (INIT, 0),
            (ADD, 0),
            (JBS, 0),
            (SHB, 0),
            (MD, 0),
            (constants::family::PUBLIC_INPUT, 0),
            (constants::family::PUBLIC_OUTPUT, 0)
        ]
    );
    for (family, want) in [(SHB, (21, 61, 10)), (MD, (21, 54, 9))] {
        let a = &setup.vk.circuit(family).expect("a circuit").artifact;
        assert_eq!((a.memory.len(), a.witness.len(), a.setup.len()), want);
    }

    let shift = shard_columns(&setup, &archive, SHB, 0, &[]).expect("the honest shift shard");
    let muldiv = shard_columns(&setup, &archive, MD, 0, &[]).expect("the honest mul/div shard");

    // The residue twin.
    let r = alu_row(
        &shift,
        sb::KINDS[sb_kind::SRA as usize],
        sb::RESIDUE,
        "`sra` that discards a bit",
    );
    let residue = at(&shift, sb::RESIDUE, r);
    h.assert_rejects(
        &tamper(vec![cell(SHB, sb::RESIDUE, r, residue + Fr::ONE)]),
        (SHB, 0),
        CONSTRAINT,
    );

    // The product-high twin.
    let r = alu_row(
        &muldiv,
        md::KINDS[md_kind::MULH as usize],
        md::P_HIGH,
        "`mulh` whose product has a high half",
    );
    let high = at(&muldiv, md::P_HIGH, r);
    h.assert_rejects(
        &tamper(vec![cell(MD, md::P_HIGH, r, high + Fr::ONE)]),
        (MD, 0),
        CONSTRAINT,
    );

    // A generic-channel count, in a second class.
    let m = at(&shift, sb::MULTIPLICITIES[2], 0);
    h.assert_rejects(
        &tamper(vec![cell(SHB, sb::MULTIPLICITIES[2], 0, m + Fr::ONE)]),
        (SHB, 0),
        lookup(lookup_channel::GENERIC),
    );

    // A pc read timestamp, in a third.
    let read_ts = frame(PC, FIELD_READ_TS);
    let r = (1..ALU_PADDING)
        .find(|&i| at(&muldiv, read_ts, i) != Fr::ZERO)
        .expect("a mul/div row reading a pc written before it");
    let ts = at(&muldiv, read_ts, r);
    h.assert_rejects(
        &tamper(vec![cell(MD, read_ts, r, ts - Fr::ONE)]),
        (MD, 0),
        MEMORY,
    );

    // The negative control.
    assert_eq!(at(&shift, frame(PC, FIELD_MASK), ALU_PADDING), Fr::ZERO);
    assert_eq!(at(&muldiv, frame(PC, FIELD_MASK), ALU_PADDING), Fr::ZERO);
    h.assert_verifies(
        &tamper(vec![
            cell(SHB, sb::POW, ALU_PADDING, f(7)),
            cell(SHB, sb::BYTES_AND[0], ALU_PADDING, f(5)),
        ]),
        (SHB, 0),
    );
    h.assert_verifies(
        &tamper(vec![
            cell(MD, md::R_INV, ALU_PADDING, f(7)),
            cell(MD, md::D_INV, ALU_PADDING, f(9)),
        ]),
        (MD, 0),
    );
}

/// The row of `columns` past every live one: `guests/mem` runs 174 cycles in
/// its largest family, so a row here is padding in all five.
const MEM_PADDING: usize = 1000;

/// The `ram` query's slot in the two memory families' frame,
/// `pc rs1 rs2 load ram rd`, and the atomics family's width. A slot is a
/// position in the family's own query list, so these differ from the add/sub
/// constants above.
const MEM_RAM: usize = 4;
const AT_WIDTH: usize = 5;

/// S19 acceptance 8, one twin per family and two refusal classes on screen.
/// The honest `mem` statement — five execution shards of `2^20` rows and, for
/// the first time in this file, a `ZERO_WINDOWS` shard — verifies (the harness
/// asserts it); its structural counts are `docs/spec/memory-ops.md` §3.1, §4.3
/// and §6.2's; and then, each refused in its class:
///
/// - **the old-word twin.** The RAM query's `read_value` on an `sw` row, moved
///   by one. The stage prompt names "one loaded-value cell: no gate reads it",
///   and for a *loaded* value that is not so — the frame's own
///   `load_writes_back` gate reads it, and so does `rd_value_rule`. The cell
///   with the stated property in this family is the word a **store**
///   overwrites: `ram` is not in `FRAME_READ_ONLY`, no `mem_word` gate reads
///   its read value, and none of the family's eighteen obligations touches it.
///   So every gate and every bound still holds, and the refusal comes from the
///   permutation product alone — the read tuple matches no write —
///   `MemoryArgument` at `verify_shard` step 10, which is what the item is
///   testing.
/// - **the splice twin.** One `low` cell of a sub-word access, raised by one.
///   `low` is the bytes below the accessed sub-word; `splice_rule` balances the
///   word with it and `low_scaled = 2·low·pcopow` is the copower half of its
///   bound, so the circuit refuses it: `Constraint`. This is the stage's named
///   `mem_subword` twin.
/// - **the old-value twin.** One `rd_selected` cell of an AMO, raised by one.
///   Every AMO writes the **old** word to `rd`, which `rd_value_rule` is;
///   `Constraint`. This is the stage's named `atomics` twin.
/// - **a decoder count**, in a third class: `Lookup { DECODER }`.
///
/// The negative control follows: cells nothing reads on an all-zero padding row
/// — `mem_word`'s `word_index_hi`, whose three obligations are switched off
/// where `m_pc` is 0; `mem_subword`'s `pcopow`, free there because `p_rule`
/// makes `p` zero and `pcopow_rule` then reads `0 = 0`; and `atomics`' `sum_hi`
/// and `cmp_gap_hi`, whose only readers are their own `RANGE16` obligations,
/// also under `m_pc`. All of them verify.
///
/// `lo` is **not** among them, which is worth recording: `lo_rule` is ungated,
/// so it pins `lo` to `rs2` on a padding row as much as on a live one. That is
/// the tighter circuit, not a defect — it is the shape S18's `add_rule` and
/// `old_bytes_rule` have too — and it is why the control moves a bounded
/// column's high chunk instead.
#[test]
#[ignore = "five 2^20-row execution shards, and the honest statement beside a re-proof: 16.9 GB"]
fn s19_a8_the_old_word_the_splice_and_the_old_value_are_pinned() {
    use constants::extra_mask::atomics as at_kind;
    use constants::extra_mask::mem_subword as ms_kind;
    use constants::extra_mask::mem_word as mw_kind;
    use constants::family::ZERO_WINDOWS as ZERO;
    use constants::family::{ATOMICS as AT, MEM_SUBWORD as MS, MEM_WORD as MW};
    use constraints::{atomics as at_circuit, mem_subword as ms, mem_word as mw};

    let setup = common::mem_setup();
    let archive = common::mem_archive(&setup.program);
    let h = TamperHarness::new(&setup, &archive);

    // The structural counts: nine shards, the first `ZERO_WINDOWS` one any
    // acceptance statement has had, S-IO's two public value ones, and each new
    // family's committed width. `ADVICE_WINDOWS` proves none, this guest having
    // no advice.
    let (public, proofs) = h.honest();
    assert_eq!(public.shard_counts, vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 0]);
    assert_eq!(public.windows, vec![8191]);
    let shards: Vec<(u32, u32)> = proofs.iter().map(|p| (p.family, p.shard_index)).collect();
    assert_eq!(
        shards,
        vec![
            (INIT, 0),
            (ZERO, 0),
            (ADD, 0),
            (JBS, 0),
            (MW, 0),
            (MS, 0),
            (AT, 0),
            (constants::family::PUBLIC_INPUT, 0),
            (constants::family::PUBLIC_OUTPUT, 0)
        ]
    );
    for (family, want) in [(MW, (31, 24, 7)), (MS, (31, 55, 10)), (AT, (26, 54, 9))] {
        let a = &setup.vk.circuit(family).expect("a circuit").artifact;
        assert_eq!(
            (a.memory.len(), a.witness.len(), a.setup.len()),
            want,
            "family {family}"
        );
    }

    let word = shard_columns(&setup, &archive, MW, 0, &public.windows).expect("the mem_word shard");
    let sub =
        shard_columns(&setup, &archive, MS, 0, &public.windows).expect("the mem_subword shard");
    let atomic =
        shard_columns(&setup, &archive, AT, 0, &public.windows).expect("the atomics shard");

    // The old-word twin: the word an `sw` overwrites, which no gate reads.
    let old = frame(MEM_RAM, FIELD_READ_VALUE);
    let r = alu_row(
        &word,
        mw::KINDS[mw_kind::SW as usize],
        old,
        "sw over a nonzero word",
    );
    let value = at(&word, old, r);
    h.assert_rejects(
        &tamper(vec![cell(MW, old, r, value + Fr::ONE)]),
        (MW, 0),
        MEMORY,
    );

    // The splice twin: one `low` cell of a sub-word access.
    let r = alu_row(
        &sub,
        ms::KINDS[ms_kind::SB as usize],
        ms::LOW,
        "sb at a nonzero byte offset",
    );
    let value = at(&sub, ms::LOW, r);
    h.assert_rejects(
        &tamper(vec![cell(MS, ms::LOW, r, value + Fr::ONE)]),
        (MS, 0),
        CONSTRAINT,
    );

    // The old-value twin: the value an AMO writes to `rd`.
    let sel = rd_selected(AT_WIDTH);
    let r = alu_row(
        &atomic,
        at_circuit::KINDS[at_kind::AMOADD_W as usize],
        sel,
        "amoadd over a nonzero word",
    );
    let value = at(&atomic, sel, r);
    h.assert_rejects(
        &tamper(vec![cell(AT, sel, r, value + Fr::ONE)]),
        (AT, 0),
        CONSTRAINT,
    );

    // A decoder count, in a third class.
    let m = at(&sub, ms::MULTIPLICITIES[3], 0);
    h.assert_rejects(
        &tamper(vec![cell(MS, ms::MULTIPLICITIES[3], 0, m + Fr::ONE)]),
        (MS, 0),
        lookup(lookup_channel::DECODER),
    );

    // The negative control: cells nothing reads on an all-zero padding row.
    for columns in [&word, &sub, &atomic] {
        assert_eq!(at(columns, frame(PC, FIELD_MASK), MEM_PADDING), Fr::ZERO);
    }
    h.assert_verifies(
        &tamper(vec![cell(MW, mw::WORD_INDEX_HI, MEM_PADDING, f(7))]),
        (MW, 0),
    );
    h.assert_verifies(
        &tamper(vec![cell(MS, ms::PCOPOW, MEM_PADDING, f(9))]),
        (MS, 0),
    );
    h.assert_verifies(
        &tamper(vec![
            cell(AT, at_circuit::SUM_HI, MEM_PADDING, f(11)),
            cell(AT, at_circuit::CMP_GAP_HI, MEM_PADDING, f(13)),
        ]),
        (AT, 0),
    );
}

// ---------------------------------------------------------------------------
// S21: the delegation circuit's cells, and the anchor's linkage
// ---------------------------------------------------------------------------

/// S21 acceptance 5 and 6, over `guests/keccak-test`: nine shards — six
/// execution families at `2^20`, the two windows, and the `KECCAK_F`
/// delegation shard at `2^8`, which is what the count below asserts.
///
/// **5**, the circuit cell: one state bit and one written word of the
/// delegation witness, each corrupted alone, each refused by the gate that
/// reads it — `Constraint` — with the honest twin passing and the structural
/// counts on screen beside them.
///
/// **6**, the linkage: the three anchor twins of `docs/spec/delegation.md`
/// §5.2, run through the family-parameterized helper every later family invokes by
/// name. They are the block's, not one shard's: a dropped invocation's only
/// symptom is the cross-shard root product, and that check reads the statement
/// rather than a proof (`docs/spec/block-proof.md` §3).
#[test]
#[ignore]
fn s21_a5_a6_the_delegation_witness_and_the_anchor_are_pinned() {
    use constants::family::KECCAK_F as KEC;
    use constants::family::ZERO_WINDOWS as ZERO;
    use constants::{delegation, keccak as k};
    use constraints::keccak as kec;

    let setup = common::keccak_setup();
    let archive = common::keccak_archive(&setup.program);
    let h = TamperHarness::new(&setup, &archive);

    // The structural counts. Eleven shards — six `2^20` execution ones, the two
    // `2^16` windows, one `2^8` delegation shard and S-IO's two `2^8` public
    // value ones — and the delegation circuit's width: 204 memory columns
    // (`cycle`, `live`, `base`, `anchor_value` and four a frame word) and 3,560
    // witness ones (the state's 1,600 bits, 38 gap bits a read, and the frame
    // pointer's 60). The delegation shard is no longer the last: S-IO's
    // families take the highest ids, and the statement's tail is ascending.
    let (public, proofs) = h.honest();
    let shards: Vec<(u32, u32)> = proofs.iter().map(|p| (p.family, p.shard_index)).collect();
    assert_eq!(shards.len(), 11, "eleven shards: {shards:?}");
    assert_eq!(
        &shards[shards.len() - 3..],
        &[
            (KEC, 0),
            (constants::family::PUBLIC_INPUT, 0),
            (constants::family::PUBLIC_OUTPUT, 0)
        ]
    );
    assert!(shards.contains(&(INIT, 0)) && shards.contains(&(ZERO, 0)));
    let a = &setup.vk.circuit(KEC).expect("a keccak circuit").artifact;
    assert_eq!(
        (a.memory.len(), a.witness.len(), a.setup.len()),
        (4 + 4 * k::FRAME_WORDS, 3560, 0)
    );
    assert_eq!(a.trace_vars, common::KECCAK_VARS);

    // Acceptance 5. The invocation rows are the guest's ten, in order; the
    // twins take the first, found by its mask rather than by its number.
    let columns = shard_columns(&setup, &archive, KEC, 0, &public.windows)
        .expect("the delegation shard's columns");
    let at = |address: PolyAddress, row: usize| {
        columns
            .iter()
            .find(|(a, _)| *a == address)
            .unwrap_or_else(|| panic!("the shard has no {address}"))
            .1
            .get(row)
    };
    let live_row = (0..1 << common::KECCAK_VARS)
        .find(|r| at(kec::LIVE, *r) == Fr::ONE)
        .expect("a live invocation");
    let padding_row = (0..1 << common::KECCAK_VARS)
        .find(|r| at(kec::LIVE, *r) == Fr::ZERO)
        .expect("a padding row");
    let keccak_cell = |address, row, value| Cell {
        family: KEC,
        shard: 0,
        address,
        row,
        value,
    };

    // A flipped input state bit: the word it recomposes no longer matches, and
    // `input_w{j}` is the gate that says so. Flipping the word with it moves
    // the refusal to the permutation's own output, which is the other half of
    // the same statement — the circuit is what ties the two together.
    let bit = at(kec::in_bit(0), live_row);
    h.assert_rejects(
        &tamper(vec![keccak_cell(kec::in_bit(0), live_row, Fr::ONE - bit)]),
        (KEC, 0),
        CONSTRAINT,
    );
    let word = at(kec::word(0, kec::WORD_READ_VALUE), live_row);
    h.assert_rejects(
        &tamper(vec![
            keccak_cell(kec::in_bit(0), live_row, Fr::ONE - bit),
            keccak_cell(
                kec::word(0, kec::WORD_READ_VALUE),
                live_row,
                word + Fr::ONE - bit - bit,
            ),
        ]),
        (KEC, 0),
        CONSTRAINT,
    );
    // A corrupted written word: the permutation says what it must be.
    let out = at(kec::word(7, kec::WORD_WRITE_VALUE), live_row);
    h.assert_rejects(
        &tamper(vec![keccak_cell(
            kec::word(7, kec::WORD_WRITE_VALUE),
            live_row,
            out + Fr::ONE,
        )]),
        (KEC, 0),
        CONSTRAINT,
    );
    // And a gap bit, which is the frame read's only bound.
    h.assert_rejects(
        &tamper(vec![keccak_cell(kec::gap_bit(3, 0), live_row, f(2))]),
        (KEC, 0),
        CONSTRAINT,
    );

    // The negative control: a padding row's cells that every gate of the family
    // really does gate off `live` — a gap bit, whose `gap_w{j}` carries the
    // mask on every product, and a frame-pointer headroom bit, whose
    // `base_in_window` does too.
    h.assert_verifies(
        &tamper(vec![
            keccak_cell(kec::gap_bit(5, 7), padding_row, Fr::ONE),
            keccak_cell(kec::base_room_bit(3), padding_row, Fr::ONE),
        ]),
        (KEC, 0),
    );
    // And its other half, which is the sharper statement: **`in_bit` is not
    // free on a padding row**, because `input_w{j}` is ungated. It does not
    // need the mask on an honest row — every term is 0 there — but that also
    // means a padding row's state bits are pinned to the words they recompose,
    // which are 0. Setting bit 11 asks word 0 to be 2^11 and `input_w0`
    // refuses it. The distinction matters: a reviewer reading "every gate is
    // gated on live" would expect this cell to be free, and it is not
    // (`docs/spec/constraint-manifest.md` §12.5, §12.10).
    h.assert_rejects(
        &tamper(vec![keccak_cell(kec::in_bit(11), padding_row, Fr::ONE)]),
        (KEC, 0),
        CONSTRAINT,
    );

    // Acceptance 6. The requesting rows are the add/sub family's delegation
    // ecalls, found by the mirror query's own mask.
    let alu = shard_columns(&setup, &archive, ADD, 0, &public.windows).expect("the add/sub shard");
    let alu_at = |address: PolyAddress, row: usize| {
        alu.iter()
            .find(|(a, _)| *a == address)
            .unwrap_or_else(|| panic!("the add/sub shard has no {address}"))
            .1
            .get(row)
    };
    let requests: Vec<usize> = (0..1 << common::ADD_VARS)
        .filter(|r| alu_at(frame(DELEG, FIELD_MASK), *r) == Fr::ONE)
        .collect();
    assert_eq!(
        requests.len() as u64,
        common::KECCAK_INVOCATIONS,
        "one request a permutation"
    );
    // The invocation that pairs with request 0 is the one at its cycle: the
    // anchor binds them there and nowhere else.
    let cycle_of = |row: usize| alu_at(CYCLE, row);
    let paired = (0..1 << common::KECCAK_VARS)
        .find(|r| at(kec::LIVE, *r) == Fr::ONE && at(kec::CYCLE, *r) == cycle_of(requests[0]))
        .expect("the invocation at the request's cycle");
    assert_eq!(
        at(kec::BASE, paired),
        alu_at(frame(DELEG, FIELD_ADDR), requests[0]),
        "and at its frame base"
    );
    assert_eq!(
        (
            alu_at(frame(DELEG, FIELD_READ_TS), requests[0]),
            alu_at(frame(DELEG, FIELD_READ_VALUE), requests[0])
        ),
        (Fr::ZERO, Fr::ZERO),
        "an honest request's mirror read is the answer tuple, stamped 0"
    );
    assert_eq!(
        delegation::ANCHOR_DELTA,
        constraints::memory::FRAME_DELTA[DELEG],
        "the anchor's slot is the mirror query's"
    );

    checker::assert_anchor_twins_refused(
        &h,
        &checker::AnchorTwins {
            requester: (ADD, 0),
            delegation: (KEC, 0),
            request: requests[0],
            invocation: paired,
            other_request: requests[1],
            rd_selected: rd_selected(WIDTH),
            cycle: CYCLE,
            mirror_read_ts: frame(DELEG, FIELD_READ_TS),
            mirror_read_value: frame(DELEG, FIELD_READ_VALUE),
            mirror_write_value: frame(DELEG, FIELD_WRITE_VALUE),
            live: kec::LIVE,
            anchor_value: kec::ANCHOR_VALUE,
        },
    );
}

// ---------------------------------------------------------------------------
// S23 acceptances 5 and 6: the two recursion delegations' witness and anchor
// ---------------------------------------------------------------------------

/// Acceptance 5: a corrupted cell in each new family's witness is refused, the
/// honest twin passes, and the structural counts hold. Acceptance 6: the
/// anchor's twins, per family, through the frozen helper.
///
/// `#[ignore]`d for the reason every twin in this file is: it proves
/// `guests/recursion-ops`' block once honestly and again per twin.
#[test]
#[ignore]
fn s23_a5_a6_the_recursion_witnesses_and_anchors_are_pinned() {
    use constants::family::{FR_ARITH as FA, POSEIDON2 as P2};
    use constants::{delegation, fr_arith as fa, poseidon2 as p2};
    use constraints::{fr_arith as fa_c, poseidon2 as p2_c};

    let setup = common::recursion_setup();
    let archive = common::recursion_archive(&setup.program);
    let h = TamperHarness::new(&setup, &archive);

    // The structural counts: a shard of each new family, in id order after
    // every execution shard, each its circuit's width. They are **not** last
    // since S-IO, whose two public value families take higher ids and prove one
    // shard each; `ADVICE_WINDOWS` proves none, this guest having no advice.
    let (public, proofs) = h.honest();
    let shards: Vec<(u32, u32)> = proofs.iter().map(|p| (p.family, p.shard_index)).collect();
    assert_eq!(
        &shards[shards.len() - 4..],
        &[
            (P2, 0),
            (FA, 0),
            (constants::family::PUBLIC_INPUT, 0),
            (constants::family::PUBLIC_OUTPUT, 0)
        ],
        "the two delegation shards sort after the execution ones: {shards:?}"
    );
    for (family, memory, witness) in [
        (P2, 4 + 4 * p2::FRAME_WORDS, p2_c::WITNESS_COLUMNS),
        (FA, 4 + 4 * fa::FRAME_WORDS, fa_c::WITNESS_COLUMNS),
    ] {
        let a = &setup
            .vk
            .circuit(family)
            .unwrap_or_else(|| panic!("a circuit for {}", program::family_name(family)))
            .artifact;
        assert_eq!(
            (a.memory.len(), a.witness.len(), a.setup.len()),
            (memory, witness, 0)
        );
        assert_eq!(a.trace_vars, common::DELEGATION_VARS);
    }

    let rows = 1usize << common::DELEGATION_VARS;
    let columns_of = |family: u32| {
        shard_columns(&setup, &archive, family, 0, &public.windows).unwrap_or_else(|e| {
            panic!(
                "the {} shard's columns: {e:?}",
                program::family_name(family)
            )
        })
    };
    let cell_of = |family: u32, address, row, value| Cell {
        family,
        shard: 0,
        address,
        row,
        value,
    };

    // --- POSEIDON2: a mid-round state cell. The written lane is what the
    // permutation's last layer compares against, so moving one word of it is
    // refused by the round block rather than by any frame gate.
    let p2_columns = columns_of(P2);
    let p2_at = |address: PolyAddress, row: usize| {
        p2_columns
            .iter()
            .find(|(a, _)| *a == address)
            .unwrap_or_else(|| panic!("the poseidon2 shard has no {address}"))
            .1
            .get(row)
    };
    let p2_live = (0..rows)
        .find(|r| p2_at(p2_c::LIVE, *r) == Fr::ONE)
        .expect("a live invocation");
    let p2_pad = (0..rows)
        .find(|r| p2_at(p2_c::LIVE, *r) == Fr::ZERO)
        .expect("a padding row");
    // A written lane word, moved with the bit it decomposes so the frame's own
    // recomposition still holds and the refusal is the permutation's.
    let word = p2_at(p2_c::word(0, p2_c::WORD_WRITE_VALUE), p2_live);
    let bit0 = p2_at(p2_c::value_bit(p2::WIDTH, 0, 0), p2_live);
    h.assert_rejects(
        &tamper(vec![
            cell_of(
                P2,
                p2_c::word(0, p2_c::WORD_WRITE_VALUE),
                p2_live,
                word + Fr::ONE - bit0 - bit0,
            ),
            cell_of(
                P2,
                p2_c::value_bit(p2::WIDTH, 0, 0),
                p2_live,
                Fr::ONE - bit0,
            ),
        ]),
        (P2, 0),
        CONSTRAINT,
    );
    // An input lane word alone: the permutation's output no longer matches.
    let in_word = p2_at(p2_c::word(0, p2_c::WORD_READ_VALUE), p2_live);
    h.assert_rejects(
        &tamper(vec![cell_of(
            P2,
            p2_c::word(0, p2_c::WORD_READ_VALUE),
            p2_live,
            in_word + Fr::ONE,
        )]),
        (P2, 0),
        CONSTRAINT,
    );
    // The control: a padding row's gap bit, whose gate carries the mask on
    // every product, is genuinely free.
    h.assert_verifies(
        &tamper(vec![cell_of(P2, p2_c::gap_bit(5, 7), p2_pad, Fr::ONE)]),
        (P2, 0),
    );

    // --- FR_ARITH: a corrupted op result. The result's word and its bit move
    // together, so the frame's recomposition holds and what refuses it is
    // `out_rule` — the gate that says the operation was performed.
    let fa_columns = columns_of(FA);
    let fa_at = |address: PolyAddress, row: usize| {
        fa_columns
            .iter()
            .find(|(a, _)| *a == address)
            .unwrap_or_else(|| panic!("the fr_arith shard has no {address}"))
            .1
            .get(row)
    };
    let fa_live = (0..rows)
        .find(|r| fa_at(fa_c::LIVE, *r) == Fr::ONE)
        .expect("a live invocation");
    let fa_pad = (0..rows)
        .find(|r| fa_at(fa_c::LIVE, *r) == Fr::ZERO)
        .expect("a padding row");
    let out = fa_at(fa_c::word(fa::OUT_WORD, fa_c::WORD_WRITE_VALUE), fa_live);
    h.assert_rejects(
        &tamper(vec![cell_of(
            FA,
            fa_c::word(fa::OUT_WORD, fa_c::WORD_WRITE_VALUE),
            fa_live,
            out + Fr::ONE,
        )]),
        (FA, 0),
        CONSTRAINT,
    );
    // The product helper, which is what buys the degree: moving it alone
    // breaks `prod_rule`.
    let prod = fa_at(fa_c::prod(), fa_live);
    h.assert_rejects(
        &tamper(vec![cell_of(FA, fa_c::prod(), fa_live, prod + Fr::ONE)]),
        (FA, 0),
        CONSTRAINT,
    );
    // And the control.
    h.assert_verifies(
        &tamper(vec![cell_of(FA, fa_c::gap_bit(5, 7), fa_pad, Fr::ONE)]),
        (FA, 0),
    );

    // --- The anchor, per family, through the frozen helper. Nothing here is
    // either family's: the anchor is one mechanism.
    let alu = shard_columns(&setup, &archive, ADD, 0, &public.windows).expect("the add/sub shard");
    let alu_at = |address: PolyAddress, row: usize| {
        alu.iter()
            .find(|(a, _)| *a == address)
            .unwrap_or_else(|| panic!("the add/sub shard has no {address}"))
            .1
            .get(row)
    };
    assert_eq!(
        delegation::ANCHOR_DELTA,
        constraints::memory::FRAME_DELTA[DELEG],
        "the anchor's slot is the mirror query's"
    );
    for (family, live, anchor_value, tag) in [
        (
            P2,
            p2_c::LIVE,
            p2_c::ANCHOR_VALUE,
            constants::address_space::DELEGATION_POSEIDON2,
        ),
        (
            FA,
            fa_c::LIVE,
            fa_c::ANCHOR_VALUE,
            constants::address_space::DELEGATION_FR_ARITH,
        ),
    ] {
        // The requesting rows of *this* type, told apart from the other's by
        // the `deleg_space` column — which is the whole point of that column.
        let requests: Vec<usize> = (0..1 << common::ADD_VARS)
            .filter(|r| {
                alu_at(frame(DELEG, FIELD_MASK), *r) == Fr::ONE
                    && alu_at(constraints::memory::deleg_space(WIDTH), *r) == f(tag as u64)
            })
            .collect();
        assert!(
            requests.len() >= 2,
            "{} needs two requests for the replay twin, and has {}",
            program::family_name(family),
            requests.len()
        );
        let columns = columns_of(family);
        let at = |address: PolyAddress, row: usize| {
            columns
                .iter()
                .find(|(a, _)| *a == address)
                .unwrap_or_else(|| panic!("the shard has no {address}"))
                .1
                .get(row)
        };
        let paired = (0..rows)
            .find(|r| at(live, *r) == Fr::ONE && at(CYCLE, *r) == alu_at(CYCLE, requests[0]))
            .expect("the invocation at the request's cycle");
        checker::assert_anchor_twins_refused(
            &h,
            &checker::AnchorTwins {
                requester: (ADD, 0),
                delegation: (family, 0),
                request: requests[0],
                invocation: paired,
                other_request: requests[1],
                rd_selected: rd_selected(WIDTH),
                cycle: CYCLE,
                mirror_read_ts: frame(DELEG, FIELD_READ_TS),
                mirror_read_value: frame(DELEG, FIELD_READ_VALUE),
                mirror_write_value: frame(DELEG, FIELD_WRITE_VALUE),
                live,
                anchor_value,
            },
        );
    }
}
