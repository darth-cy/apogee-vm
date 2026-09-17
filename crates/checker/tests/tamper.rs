//! S16's and S17's tamper twins, through `TamperHarness`: one statement —
//! `guests/addsub`, or S17's `guests/control` — proved honestly once per test,
//! then proved again with one tamper as an honest prover would prove the
//! tampered witness, and one shard verified through `verify_shard`. Each twin
//! asserts the class of the check that refuses it
//! (`docs/spec/shard-proof.md` §6).
//!
//! **`#[ignore]`d, and run by name with `--include-ignored --test-threads=1`**:
//! the add/sub shard is `2^20` rows and a statement's proof peaks at 8.6 GB —
//! 9.3 GB with the honest statement the harness holds beside a re-proof — and
//! `control`'s has two execution shards of that height, which puts the file's
//! peak at 11.3 GB.
//! The rows these tampers edit are `crates/checker/tests/add_sub.rs`'s, which
//! runs in ordinary CI.
//!
//! `addsub`'s rows are its 29 cycles in order: row 0 `lui t0`, row 4
//! `add t2, t0, t1` (carrying), row 5 `add t3, t1, t1`, row 8 `add x0, t0, t1`
//! (carrying, discarded), row 27 `addi a7, x0, 93`, row 28 the exit. Everything
//! from row 29 up is padding.

#[path = "../../prover/tests/common/mod.rs"]
mod common;

use checker::{Cell, Tamper, TamperHarness};
use constants::extra_mask::jump_branch_slt as kind;
use constants::family::JUMP_BRANCH_SLT as JBS;
use constants::family::{ADD_SUB_LUI_AUIPC as ADD, INIT_TEARDOWN as INIT};
use constants::lookup_channel;
use constraints::add_sub::{DECODED, KINDS, MULTIPLICITIES, NEXT_PC_HI, PC_WRAP, RD_HI, WRAP};
use constraints::jump_branch_slt as jbs;
use constraints::memory::{
    frame, gap_hi, rd_inv, rd_is_zero, rd_selected, CYCLE, FIELD_ADDR, FIELD_MASK, FIELD_READ_TS,
    FIELD_READ_VALUE, FIELD_WRITE_VALUE,
};
use constraints::PolyAddress;
use field::Fr;
use prover::{shard_columns, ProverSetup};
use trace::{build_multiplicities, Role, TraceArchive};
use verifier::VerifyError;

const WIDTH: usize = 7;
const PC: usize = 0;
const RS1: usize = 1;
const RS2: usize = 2;
const RAM: usize = 5;
const RD: usize = 6;

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
