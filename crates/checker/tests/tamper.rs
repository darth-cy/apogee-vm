//! Tamper twins through `TamperHarness`: one statement — `guests/addsub` or
//! `guests/control` — proved honestly once per test, then proved again with one tamper as an honest prover would prove the
//! tampered witness, and one shard verified through `verify_shard`, or the
//! block through `verify_block`. Each twin asserts the class of the check that
//! refuses it (`docs/spec/proof.md` §6).
//!
//! **`#[ignore]`d, and run by name with `--include-ignored --test-threads=1`**:
//! the add/sub shard is `2^20` rows and a statement's proof peaks at 3.9 GB —
//! 4.0 GB with the honest statement the harness holds beside a re-proof — and
//! `control`'s has two execution shards of that height, 5.4 GB. Every family's
//! rows are held to their circuits row by row in `tests/families.rs`, which
//! runs in ordinary CI.
//!
//! `addsub`'s rows are its 39 cycles in order: row 0 `lui t0`, row 4
//! `add t2, t0, t1` (carrying out of both words), row 5 `add t3, t1, t1`, row
//! 15 `add x0, t0, t1` (carrying, discarded), row 37 `addi a7, x0, 93`, row 38
//! the exit, at cycle 39. Everything from row 39 up is padding.

#[path = "../../prover/tests/common/mod.rs"]
mod common;

use checker::{Cell, Tamper, TamperHarness};
use constants::extra_mask::jump_branch_slt as kind;
use constants::family::JUMP_BRANCH_SLT as JBS;
use constants::family::{ADD_SUB_LUI_AUIPC as ADD, INIT_TEARDOWN as INIT};
use constants::lookup_channel;
use constraints::memory::CYCLE;
use constraints::PolyAddress;
use field::Fp;
use prover::{shard_columns, ProverSetup};
use trace::{Role, TraceArchive};
use verifier::VerifyError;

/// The committed column `name` of `family`'s circuit.
fn col(family: u32, name: &str) -> PolyAddress {
    constraints::family_circuit(family, 20)
        .expect("the family's circuit at 2^20")
        .artifact
        .column(name)
        .unwrap_or_else(|| panic!("family {family} has no column `{name}`"))
}

/// The columns of the frame's `rd` query, by field: the five a query has and
/// the two words a register adds.
const RD_FIELDS: [&str; 7] = [
    "rd_mask",
    "rd_addr",
    "rd_read_ts",
    "rd_read_value",
    "rd_write_value",
    "rd_read_hi",
    "rd_write_hi",
];

const CONSTRAINT: VerifyError = VerifyError::Constraint { layer: 0 };
const MEMORY: VerifyError = VerifyError::MemoryArgument("");
/// A twin only an opening of the committed columns refuses: no gate, no
/// channel and no memory argument sees it.
const OPENING: VerifyError = VerifyError::Opening("");

fn lookup(channel: u32) -> VerifyError {
    VerifyError::Lookup { channel }
}

fn f(v: u64) -> Fp {
    Fp::from_u64(v)
}

fn cell(family: u32, name: &str, row: usize, value: Fp) -> Cell {
    at(family, col(family, name), row, value)
}

fn at(family: u32, address: PolyAddress, row: usize, value: Fp) -> Cell {
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

/// Three distinct classes on screen: a semantics cell, `Constraint`; a memory
/// event's value and its timestamp, `MemoryArgument`; a lookup multiplicity,
/// `Lookup`.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 3.9 GB"]
fn a2_a3_a4_a_semantics_a_memory_and_a_multiplicity_cell_fail_in_three_classes() {
    let setup = common::setup();
    let archive = common::archive(&setup.program);
    let h = TamperHarness::new(&setup, &archive);

    // A semantics cell: the carrying add's low carry, cleared; and the
    // non-carrying add's computed value moved.
    assert_eq!(h.cell(ADD, 0, col(ADD, "c0"), 4), Fp::ONE);
    h.assert_rejects(
        &tamper(vec![cell(ADD, "c0", 4, Fp::ZERO)]),
        (ADD, 0),
        CONSTRAINT,
    );
    let sel = h.cell(ADD, 0, col(ADD, "rd_selected"), 5);
    h.assert_rejects(
        &tamper(vec![cell(ADD, "rd_selected", 5, sel + Fp::ONE)]),
        (ADD, 0),
        CONSTRAINT,
    );

    // A memory event: a teardown value no gate reads, and a pc read's
    // timestamp one lower — its gap chunk still in range and its multiplicity
    // recounted — both pinned by the multiset alone.
    let word = h.cell(INIT, 0, PolyAddress::Memory(1), IMAGE_ROW);
    h.assert_rejects(
        &tamper(vec![at(
            INIT,
            PolyAddress::Memory(1),
            IMAGE_ROW,
            word + Fp::ONE,
        )]),
        (INIT, 0),
        MEMORY,
    );
    assert_eq!(h.cell(ADD, 0, col(ADD, "pc_read_ts"), 3), f(12));
    h.assert_rejects(
        &tamper(vec![cell(ADD, "pc_read_ts", 3, f(11))]),
        (ADD, 0),
        MEMORY,
    );

    // A multiplicity: one cell, in the range channel and in the decoder's.
    let m = h.cell(ADD, 0, col(ADD, "mult_range16"), 0);
    h.assert_rejects(
        &tamper(vec![cell(ADD, "mult_range16", 0, m + Fp::ONE)]),
        (ADD, 0),
        lookup(lookup_channel::RANGE16),
    );
    let first = 0x1_0000 / 2;
    let m = h.cell(ADD, 0, col(ADD, "mult_decoder"), first);
    assert_eq!(m, Fp::ONE, "the first instruction runs once");
    h.assert_rejects(
        &tamper(vec![cell(ADD, "mult_decoder", first, Fp::ZERO)]),
        (ADD, 0),
        lookup(lookup_channel::DECODER),
    );
}

/// The soundness floor. An unreduced low word is refused by the range
/// channel; a carry of 2 by its booleanity; an all-zero family mask by the
/// decoder channel's domain, every gate and range still holding; a `next_pc`
/// outside 32 bits by the range channel.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 3.9 GB"]
fn a7_the_soundness_floor_refuses_each_of_its_controls() {
    let setup = common::setup();
    let archive = common::archive(&setup.program);
    let h = TamperHarness::new(&setup, &archive);
    let get = |name: &str, row: usize| h.cell(ADD, 0, col(ADD, name), row);

    // Row 15, `add x0, t0, t1`: its rd write is 0 whatever it computes, so
    // these tampers reach no memory event. The low words carry, and the high
    // words, `2^32 − 1` and 0, carry only with it.
    let (a, b) = (
        small(get("rs1_read_value", 15)),
        small(get("rs2_read_value", 15)),
    );
    assert_eq!(get("rd_addr", 15), Fp::ZERO);
    assert!(a + b >= 1 << 32, "the low words carry");
    assert_eq!(
        (get("rs1_read_hi", 15), get("rs2_read_hi", 15)),
        (f(u32::MAX as u64), Fp::ZERO)
    );
    // The carry dropped, the low word left unreduced, the high word the sum
    // without the carry in: every gate holds, and the low word's range does
    // not.
    h.assert_rejects(
        &tamper(vec![
            cell(ADD, "c0", 15, Fp::ZERO),
            cell(ADD, "c1", 15, Fp::ZERO),
            cell(ADD, "rd_selected", 15, f(a + b)),
            cell(ADD, "rd_selected_hi", 15, f(u32::MAX as u64)),
            cell(ADD, "rd_hi_h16", 15, f(0xffff)),
        ]),
        (ADD, 0),
        lookup(lookup_channel::RANGE16),
    );
    h.assert_rejects(
        &tamper(vec![
            cell(ADD, "c0", 15, f(2)),
            cell(ADD, "rd_selected", 15, f(a + b) - f(1 << 33)),
            cell(ADD, "rd_selected_hi", 15, Fp::ONE),
            cell(ADD, "rd_hi_h16", 15, Fp::ZERO),
        ]),
        (ADD, 0),
        CONSTRAINT,
    );

    // Row 0, `lui t0, 0xfffff`: its mask, its kind bit and its immediate's
    // sign cleared, and its rd query dropped to match, so every gate still
    // holds.
    let zero: Vec<Cell> = [
        "decoded_extra_mask",
        "kind_lui",
        "imm_negative",
        "rd_inv",
        "rd_is_zero",
        "rd_selected",
        "rd_selected_hi",
        "rd_gap_hi",
        "rd_lo_h16",
        "rd_lo_sign",
        "rd_hi_h16",
    ]
    .iter()
    .chain(&RD_FIELDS)
    .map(|name| cell(ADD, name, 0, Fp::ZERO))
    .collect();
    h.assert_rejects(&tamper(zero), (ADD, 0), lookup(lookup_channel::DECODER));

    // Row 4: next_pc − 2^32 with a wrap of 1.
    let next = get("decoded_next_pc", 4);
    h.assert_rejects(
        &tamper(vec![
            cell(ADD, "pc_wrap", 4, Fp::ONE),
            cell(ADD, "pc_write_value", 4, next - f(1 << 32)),
            cell(ADD, "next_pc_h16", 4, Fp::ZERO),
        ]),
        (ADD, 0),
        lookup(lookup_channel::RANGE16),
    );
}

/// The harness's negative control: cells nothing reads — a padding row's gap
/// chunk, whose obligation its mask switches off, and a padding row's `rd_inv`,
/// which multiplies an address of 0 — change and the statement still verifies.
/// The harness tells a harmless edit from a harmful one.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 3.9 GB"]
fn a11_a_cell_nothing_reads_still_verifies() {
    let setup = common::setup();
    let archive = common::archive(&setup.program);
    let h = TamperHarness::new(&setup, &archive);
    h.assert_verifies(&tamper(vec![cell(ADD, "pc_gap_hi", 100, f(5))]), (ADD, 0));
    h.assert_verifies(&tamper(vec![cell(ADD, "rd_inv", 1000, f(7))]), (ADD, 0));
    // The other shard sees the same statement, and verifies too.
    h.assert_verifies(&tamper(vec![cell(ADD, "pc_gap_hi", 100, f(5))]), (INIT, 0));
}

/// The committed result is the exit status, `x10`'s final value, and the
/// teardown is what binds final values. A RAM teardown value or timestamp
/// changed, and `x10`'s final value changed while the public exit status stays
/// honest, are each refused as `MemoryArgument` — on both shards.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 3.9 GB"]
fn a13_the_teardown_binds_the_final_values() {
    let setup = common::setup();
    let archive = common::archive(&setup.program);
    let h = TamperHarness::new(&setup, &archive);
    let row = IMAGE_ROW + 5;
    let value = h.cell(INIT, 0, PolyAddress::Memory(1), row);
    let moved = tamper(vec![at(INIT, PolyAddress::Memory(1), row, value + Fp::ONE)]);
    h.assert_rejects(&moved, (INIT, 0), MEMORY);
    h.assert_rejects(&moved, (ADD, 0), MEMORY);
    let stamped = tamper(vec![at(INIT, PolyAddress::Memory(0), IMAGE_ROW + 3, f(5))]);
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
    assert_eq!(finals.reg_values[9], u64::from(common::RESULT));
    finals.reg_values[9] = u64::from(common::RESULT) + 1;
    let result = Tamper {
        cells: vec![],
        boundary: Some(finals),
    };
    assert_eq!(
        h.run(&result, (ADD, 0)),
        Err(VerifyError::MemoryArgument(
            "x10's final low word is not the exit status"
        ))
    );
    h.assert_rejects(&result, (INIT, 0), MEMORY);
}

/// A row's pc write is a cycle or more after the one it reads
/// (`docs/spec/memory.md` §2.4, §9). Row 3, at cycle 4, reads the pc row 2
/// wrote at 12, its gap 0; that read moved one later, to 13, is refused by the
/// timestamp channel, `gap_lo_pc` being −1 there. One earlier, to 11, the gap
/// is in range and the multiset alone refuses it (the `a3` tamper above).
///
/// The cycle is not the cell moved: the harness derives a shard's time window
/// from its cycle column, as an honest prover does, so a fractional cycle puts
/// the window off the clock, a `Statement` refusal before any lookup is read.
/// `crates/checker/tests/multiset.rs`' `consecutive_rows_are_a_cycle_apart`
/// holds a fractional cycle to `gap_lo_pc` in the circuit.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 3.9 GB"]
fn a_pc_read_less_than_a_cycle_before_its_write_is_refused() {
    let setup = common::setup();
    let archive = common::archive(&setup.program);
    let h = TamperHarness::new(&setup, &archive);
    assert_eq!(h.cell(ADD, 0, CYCLE, 3), f(4));
    assert_eq!(h.cell(ADD, 0, col(ADD, "pc_read_ts"), 3), f(12));
    h.assert_rejects(
        &tamper(vec![cell(ADD, "pc_read_ts", 3, f(13))]),
        (ADD, 0),
        lookup(lookup_channel::TIMESTAMP),
    );
}

/// The frame's and the halting rule's tamper targets, `docs/spec/memory.md`
/// §2.1 and §5: each refused.
///
/// - a padding row's `rd` query rewriting `x10` after the exit, and a live
///   row's `rd` write masked off — each `Constraint`; the exit row given a
///   store has no column to live in;
/// - the exit rewriting its status — `Constraint`;
/// - a row that is not the exit writing `HALT_PC`, the truncation target —
///   `Constraint`.
///
/// The image column's twin is
/// `the_image_column_moved_with_its_teardown_is_refused`.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 3.9 GB"]
fn the_frame_and_halting_targets_are_refused() {
    let setup = common::setup();
    let archive = common::archive(&setup.program);
    let h = TamperHarness::new(&setup, &archive);

    // A padding row, cycle 40, rewriting x10 from 42 to 43.
    let (public, _) = h.honest();
    let x10_ts = public.boundary.reg_ts[10];
    let forgery = vec![
        at(ADD, CYCLE, 100, f(40)),
        cell(ADD, "rd_mask", 100, Fp::ONE),
        cell(ADD, "rd_addr", 100, f(10)),
        cell(ADD, "rd_read_ts", 100, f(x10_ts)),
        cell(ADD, "rd_read_value", 100, f(42)),
        cell(ADD, "rd_write_value", 100, f(43)),
        cell(ADD, "rd_inv", 100, f(10).inverse().unwrap()),
        cell(ADD, "rd_selected", 100, f(43)),
    ];
    let mut finals = public.boundary;
    finals.reg_ts[10] = 4 * 40 + 3;
    finals.reg_values[9] = 43;
    let c8 = Tamper {
        cells: forgery,
        boundary: Some(finals),
    };
    h.assert_rejects(&c8, (ADD, 0), CONSTRAINT);

    // Row 5's rd write masked off.
    let masked: Vec<Cell> = RD_FIELDS
        .iter()
        .chain(&["rd_inv", "rd_gap_hi"])
        .map(|name| cell(ADD, name, 5, Fp::ZERO))
        .collect();
    h.assert_rejects(&tamper(masked), (ADD, 0), CONSTRAINT);

    // The exit row storing 7 into the top stack word, never written before, is
    // **unrepresentable** and so is not tried: the frame has no `ram` query,
    // no instruction routed here touching memory. A forgery with no column to
    // live in is a stronger refusal than a gate.

    // The exit rewriting a0.
    h.assert_rejects(
        &tamper(vec![
            cell(ADD, "rd_write_value", 38, f(43)),
            cell(ADD, "rd_selected", 38, f(43)),
        ]),
        (ADD, 0),
        CONSTRAINT,
    );

    // Row 37, `addi a7, x0, 93`, writing HALT_PC.
    h.assert_rejects(
        &tamper(vec![
            cell(ADD, "pc_write_value", 37, Fp::ONE),
            cell(ADD, "next_pc_h16", 37, Fp::ZERO),
        ]),
        (ADD, 0),
        CONSTRAINT,
    );
}

/// The image column and the teardown of one untouched word, moved together,
/// so the multiset still balances: refused by the opening of `S[0]` against
/// the key's commitment of the image column (`docs/spec/memory.md` §6.2).
#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 3.9 GB"]
fn the_image_column_moved_with_its_teardown_is_refused() {
    let setup = common::setup();
    let archive = common::archive(&setup.program);
    let h = TamperHarness::new(&setup, &archive);
    let row = IMAGE_ROW + 10;
    let word = h.cell(INIT, 0, PolyAddress::Setup(0), row);
    assert_eq!(word, h.cell(INIT, 0, PolyAddress::Memory(1), row));
    let twin = tamper(vec![
        at(INIT, PolyAddress::Setup(0), row, word + Fp::ONE),
        at(INIT, PolyAddress::Memory(1), row, word + Fp::ONE),
    ]);
    h.assert_rejects(&twin, (INIT, 0), OPENING);
}

/// A field element's canonical integer, which the tests only read where it is
/// a `u32`.
fn small(v: Fp) -> u64 {
    let v = v.to_u64();
    assert!(v <= u32::MAX as u64, "{v:#x} is not a u32");
    v
}

// ---------------------------------------------------------------------------
// The jump/branch/slt family, over `guests/control`
// ---------------------------------------------------------------------------

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
            // pc next_pc rs1 rs2 rd imm extra_mask: the mask is column 6, the
            // immediate's sign its bit 31.
            let mask = table.get(6, row.pc as usize / 2).expect("a live row");
            pick((mask & 0x7fff_ffff).trailing_zeros(), &row)
        })
        .expect("control runs the row the test names")
}

fn jbs_cell(name: &str, row: usize, value: Fp) -> Cell {
    cell(JBS, name, row, value)
}

/// The comparison, the pc, and the generic channel's binding. The honest,
/// branch-heavy statement verifies (the harness asserts it); then, each refused
/// in its class:
///
/// - one corrupted `lt` cell, from `BLT(1, −2^31)`, which is not taken: the
///   comparison and the branch form refuse it, `Constraint`;
/// - the same forgery carried through — `lt`, the gap's high word moved by
///   `2^32` and its high halfword with it, the equality inverse, `taken` and
///   the pc written at the branch's target — which every gate accepts: the
///   gap's range check is what refuses it, `Lookup { RANGE16 }`;
/// - the written `next_pc` of the `jalr`, moved two bytes on together with
///   the `rs1` it is formed from, every gate and bound still holding: only the
///   global memory argument refuses it, `MemoryArgument` — and again with the
///   add/sub row that wrote that `rs1` moved to match, so the register's chain
///   balances and the pc's alone does not;
/// - one generic-channel count moved, `Lookup { GENERIC }`.
///
/// And two cells nothing reads, on a padding row, still verify. The poisoned
/// packed-table twin is `a_poisoned_generic_table_row_is_refused`.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 5.4 GB"]
fn s17_a7_the_comparison_and_the_pc_are_pinned() {
    let setup = common::control_setup();
    let archive = common::control_archive(&setup.program);
    let h = TamperHarness::new(&setup, &archive);
    let columns = shard_columns(&setup, &archive, JBS, 0, &[]).expect("the honest shard");
    let get = |name: &str, row: usize| {
        let address = col(JBS, name);
        columns
            .iter()
            .find(|(a, _)| *a == address)
            .unwrap_or_else(|| panic!("no {address}"))
            .1
            .get_base(row)
    };

    // BLT(1, −2^31): not taken.
    let r = jbs_row(&setup, &archive, |bit, row| {
        bit == kind::BLT
            && row.query(Role::Rs1).map(|q| q.read_value) == Some(1)
            && row.query(Role::Rs2).map(|q| q.read_value) == Some(0xffff_ffff_8000_0000)
    });
    assert_eq!(get("cmp_lt", r), Fp::ZERO);
    assert_eq!(get("taken", r), Fp::ZERO);
    h.assert_rejects(
        &tamper(vec![jbs_cell("cmp_lt", r, Fp::ONE)]),
        (JBS, 0),
        CONSTRAINT,
    );
    // The branch's target, `pc + imm` over the immediate's low word: a carry
    // out of it is the pc's wrap.
    let target = small(get("pc_read_value", r)) + small(get("decoded_imm", r));
    let gap_hi = get("cmp_gap_hi", r) + f(1 << 32);
    h.assert_rejects(
        &tamper(vec![
            jbs_cell("cmp_lt", r, Fp::ONE),
            jbs_cell("cmp_gap_hi", r, gap_hi),
            jbs_cell("cmp_gap_hi_h16", r, get("cmp_gap_hi_h16", r) + f(1 << 16)),
            jbs_cell(
                "eq_inv",
                r,
                (get("cmp_gap_lo", r) + gap_hi).inverse().unwrap(),
            ),
            jbs_cell("taken", r, Fp::ONE),
            jbs_cell("pc_write_value", r, f(target & 0xffff_ffff)),
            jbs_cell("pc_wrap", r, f(target >> 32)),
            jbs_cell("next_pc_h16", r, f((target & 0xffff_ffff) >> 16)),
        ]),
        (JBS, 0),
        lookup(lookup_channel::RANGE16),
    );

    // The jalr: rs1 = rd, imm = -2, bit 0 of rs1 + imm set.
    let r = jalr_row(&setup, &archive);
    let v = small(get("rs1_read_value", r));
    let next = small(get("pc_write_value", r));
    assert_eq!(get("jalr_drop", r), Fp::ONE);
    assert_eq!(next, (v - 2) & !1);
    h.assert_rejects(&tamper(jalr_moved(r, v, next)), (JBS, 0), MEMORY);
    // `addi t2, t2, 3`, the add/sub row just before the jalr, wrote `v`. Its
    // write moved too, the register's read and write pair up again, and the
    // pc's is the one imbalance left. The add/sub shard is re-proved over its
    // broken gate, and only this family's shard is verified.
    let jalr_pc = small(get("pc_read_value", r)) as u32;
    let traces = archive.family_traces();
    let adds = traces.family(ADD).expect("the add/sub buffer");
    let a = (0..adds.len())
        .find(|&i| {
            let row = adds.row(i);
            row.next_pc == jalr_pc && row.query(Role::Rd).map(|q| q.write_value) == Some(v)
        })
        .expect("the add/sub row writing the jalr's rs1");
    let mut pc_only = jalr_moved(r, v, next);
    pc_only.push(cell(ADD, "rd_write_value", a, f(v + 2)));
    h.assert_rejects(&tamper(pc_only), (JBS, 0), MEMORY);

    // The generic channel's count of the ZeroEntry.
    let m = get("mult_generic", 0);
    h.assert_rejects(
        &tamper(vec![jbs_cell("mult_generic", 0, m + Fp::ONE)]),
        (JBS, 0),
        lookup(lookup_channel::GENERIC),
    );

    // A padding row's dropped bit and its equality inverse: nothing reads
    // either where every mask and kind bit is 0.
    let padding = 1000;
    assert_eq!(get("pc_mask", padding), Fp::ZERO);
    h.assert_verifies(
        &tamper(vec![
            jbs_cell("jalr_drop", padding, Fp::ONE),
            jbs_cell("eq_inv", padding, f(7)),
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
/// equality gadget computed from `rs1`, whose comparand is 0. Bit 0 and the
/// wraps are unchanged, so every gate and every bound holds; the register's
/// chain and the pc's do not.
fn jalr_moved(r: usize, v: u64, next: u64) -> Vec<Cell> {
    let moved = v + 2;
    vec![
        jbs_cell("rs1_read_value", r, f(moved)),
        jbs_cell("rs1_write_value", r, f(moved)),
        jbs_cell("rd_read_value", r, f(moved)),
        jbs_cell("pc_write_value", r, f(next + 2)),
        jbs_cell("eq_inv", r, f(moved).inverse().unwrap()),
        jbs_cell("cmp_gap_lo", r, f(moved)),
        jbs_cell("cmp_gap_lo_h16", r, f(moved >> 16)),
    ]
}

/// A packed-table cell no row looks up, poisoned — `37 AND 45` answering 0 —
/// which no gate and no channel sees: refused by the opening of the table's
/// columns against the key's setup commitment.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 5.4 GB"]
fn a_poisoned_generic_table_row_is_refused() {
    let setup = common::control_setup();
    let archive = common::control_archive(&setup.program);
    let h = TamperHarness::new(&setup, &archive);
    let and_row = 1 + 37 * 256 + 45;
    let get = |name: &str| h.cell(JBS, 0, col(JBS, name), and_row);
    assert_eq!(
        [
            "generic_tag",
            "generic_key",
            "generic_value",
            "generic_result"
        ]
        .map(get),
        [1, 37, 45, 37 & 45].map(f)
    );
    assert_eq!(get("mult_generic"), Fp::ZERO);
    let twin = tamper(vec![jbs_cell("generic_result", and_row, Fp::ZERO)]);
    h.assert_rejects(&twin, (JBS, 0), OPENING);
}
