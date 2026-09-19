//! The family fills: how each family's trace buffer becomes its circuit's
//! committed columns. `docs/spec/shard-proof.md` §8.1 and §11.
//!
//! A fill returns every `M`, `W` and `S` column but the multiplicities, which
//! the common path counts over the family's channels.

use constants::extra_mask::add_sub_lui_auipc as kind;
use constants::extra_mask::jump_branch_slt as jbs;
use constants::extra_mask::system_code;
use constants::{ecall, family, memory};
use constraints::add_sub::{
    DECODED, IS_ECALL, IS_FENCE, KINDS, NEXT_PC_HI, PC_WRAP, RD_HI, TABLE_WIDTH, WRAP,
};
use constraints::jump_branch_slt as jbs_circuit;
use constraints::memory::{frame_queries, rd_selected};
use constraints::PolyAddress;
use field::Fr;
use poly::{MultilinearPoly, PolyBacking};
use program::lookup_tables::generic_table;
use program::FamilyId;
use trace::{
    build_frame_witness, build_init_teardown_columns, build_memory_columns, Role, TraceArchive,
};

use crate::Program;

/// What a fill reads: the program, the archived execution, and which shard —
/// its family, its index, its height, and for a RAM window family its window.
pub struct ShardSource<'a> {
    pub program: &'a Program,
    pub archive: &'a TraceArchive,
    pub family: FamilyId,
    pub index: u32,
    pub height: usize,
    pub window: u32,
}

/// A family's fill: a shard's committed columns but its multiplicities, or why
/// the trace cannot be proven.
pub type Fill = fn(&ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String>;

/// The fill of `family`, or `None` for a family no circuit proves yet — the
/// registry beside `constraints::family_circuit`.
pub fn family_fill(family: FamilyId) -> Option<Fill> {
    match family {
        family::ADD_SUB_LUI_AUIPC => Some(add_sub),
        family::JUMP_BRANCH_SLT => Some(jump_branch_slt),
        family::INIT_TEARDOWN | family::ZERO_WINDOWS => Some(window),
        _ => None,
    }
}

/// A RAM window shard: `trace::build_init_teardown_columns` over its window,
/// with `S[0]`, the image column, for window 0.
fn window(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    Ok(build_init_teardown_columns(
        src.archive.memory_log(),
        &src.program.image,
        src.window,
        src.height,
    ))
}

fn u32_column(mut values: Vec<u32>, height: usize) -> MultilinearPoly {
    values.resize(height, 0);
    MultilinearPoly::new(PolyBacking::U32(values))
}

/// An `ADD_SUB_LUI_AUIPC` shard, `docs/spec/shard-proof.md` §8.1: S14's frame
/// columns over the shard's cycles, the decoded row each cycle's pc claims, the
/// kind bits, the system split, the computed `rd` value with its wrap and high
/// halfword — written over the frame's `rd_selected`, which S14's builder
/// leaves 0 on an `x0` write — `next_pc`'s wrap and high halfword, and the
/// family's decoded table as `S[0..7]`.
///
/// Refuses, naming the cycle, an ecall other than `EXIT`: S16 proves no other.
/// Panics if the trace and the decoded table disagree — a cycle at a pc the
/// table does not hold, an `rd` write or a `next_pc` that is not what the
/// instruction computes — which the emulator cannot produce.
fn add_sub(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    let fam = family::ADD_SUB_LUI_AUIPC;
    let traces = src.archive.family_traces();
    let trace = traces
        .family(fam)
        .ok_or("the archive has no ADD_SUB_LUI_AUIPC buffer")?;
    let table = src
        .program
        .tables
        .family(fam)
        .ok_or("the program has no ADD_SUB_LUI_AUIPC table")?;
    let h = src.height;
    let start = src.index as usize * h;
    let end = (start + h).min(trace.len());
    let cycles = &trace.cycle[start..end];
    let log = src.archive.memory_log();
    let queries = frame_queries(fam);
    let width = queries.len();

    let mut decoded: [Vec<u32>; 6] = Default::default();
    let mut kinds: [Vec<u32>; 6] = Default::default();
    let (mut is_ecall, mut is_fence, mut wrap) = (Vec::new(), Vec::new(), Vec::new());
    let (mut sel, mut rd_hi, mut next_pc_hi) = (Vec::new(), Vec::new(), Vec::new());
    for r in start..end {
        let row = trace.row(r);
        let slot = row.pc as usize / 2;
        let field = |column: usize| {
            table.get(column, slot).unwrap_or_else(|| {
                panic!(
                    "cycle {} runs pc {:#x}, which the ADD_SUB_LUI_AUIPC table does not hold",
                    row.cycle, row.pc
                )
            })
        };
        // lookup_tuple: pc next_pc rs1 rs2 rd imm extra_mask.
        let row_values = [field(1), field(2), field(3), field(4), field(5), field(6)];
        let (fall, imm, mask) = (row_values[0], row_values[4], row_values[5]);
        let read = |role: Role| row.query(role).map_or(0, |q| q.read_value);
        let (a, b) = (read(Role::Rs1), read(Role::Rs2));
        let bit = mask.trailing_zeros();
        let (mut ecall_row, mut fence_row) = (0, 0);
        let (value, carry) = match bit {
            kind::ADD => add(a, b),
            kind::ADDI => add(a, imm),
            kind::AUIPC => add(row.pc, imm),
            kind::SUB => (a.wrapping_sub(b), (a < b) as u32),
            kind::LUI => (imm, 0),
            kind::SYSTEM => match imm {
                system_code::ECALL if row.query(Role::Rs1).is_none() => {
                    return Err(format!(
                        "cycle {} is an ecall's transfer cycle, and S16 proves EXIT alone",
                        row.cycle
                    ))
                }
                system_code::ECALL if a == ecall::EXIT => {
                    ecall_row = 1;
                    (read(Role::Rd), 0)
                }
                system_code::ECALL => {
                    return Err(format!(
                        "cycle {} calls ecall {a}, and S16 proves EXIT alone",
                        row.cycle
                    ))
                }
                system_code::FENCE => {
                    fence_row = 1;
                    (0, 0)
                }
                other => panic!("cycle {} is a system row with code {other}", row.cycle),
            },
            other => panic!("cycle {} has kind bit {other}", row.cycle),
        };
        if let Some(rd) = row.query(Role::Rd).filter(|q| q.addr != 0) {
            assert_eq!(
                rd.write_value, value,
                "cycle {}: the trace's rd write is not what the instruction computes",
                row.cycle
            );
        }
        let want_next = match ecall_row {
            1 => memory::HALT_PC,
            _ => fall,
        };
        assert_eq!(
            row.next_pc, want_next,
            "cycle {}: the trace's next_pc is not the family's",
            row.cycle
        );
        for (column, v) in decoded.iter_mut().zip(row_values) {
            column.push(v);
        }
        for (k, column) in kinds.iter_mut().enumerate() {
            column.push((k as u32 == bit) as u32);
        }
        is_ecall.push(ecall_row);
        is_fence.push(fence_row);
        wrap.push(carry);
        sel.push(value);
        rd_hi.push(value >> 16);
        next_pc_hi.push(row.next_pc >> 16);
    }

    let mut out = build_memory_columns(log, queries, cycles, h);
    for (address, column) in build_frame_witness(log, queries, cycles, h) {
        // The computed value, not S14's masked one.
        if address != rd_selected(width) {
            out.push((address, column));
        }
    }
    out.push((rd_selected(width), u32_column(sel, h)));
    for (address, values) in DECODED.iter().zip(decoded) {
        out.push((*address, u32_column(values, h)));
    }
    for (address, values) in KINDS.iter().zip(kinds) {
        out.push((*address, u32_column(values, h)));
    }
    out.push((IS_ECALL, u32_column(is_ecall, h)));
    out.push((IS_FENCE, u32_column(is_fence, h)));
    out.push((WRAP, u32_column(wrap, h)));
    out.push((RD_HI, u32_column(rd_hi, h)));
    out.push((PC_WRAP, u32_column(Vec::new(), h)));
    out.push((NEXT_PC_HI, u32_column(next_pc_hi, h)));
    for j in 0..TABLE_WIDTH {
        out.push((PolyAddress::Setup(j as u32), table.column_poly(j)));
    }
    Ok(out)
}

/// `a + b` mod `2^32`, and its carry.
fn add(a: u32, b: u32) -> (u32, u32) {
    let (sum, carry) = a.overflowing_add(b);
    (sum, carry as u32)
}

/// A `JUMP_BRANCH_SLT` shard, `docs/spec/jump-branch-slt.md` §2: S14's frame
/// columns over the shard's cycles; the decoded row each cycle's pc claims and
/// its kind bits; the comparison of `rs1` against `cmp_rhs` — the operands'
/// high halfwords and signs, `lt`, the gap and its high halfword; `eq` and the
/// inverse of `rs1 − cmp_rhs`; `taken`; `jalr`'s dropped bit, the wrap of
/// whichever sum `next_pc` is and its high halfword; the written `rd` value
/// over the frame's `rd_selected`, which S14's builder leaves 0 on an `x0`
/// write, and its high halfword; the family's decoded table as `S[0..7]` and
/// the packed generic table as `S[7..10]`.
///
/// Panics if the trace and the decoded table disagree — a cycle at a pc the
/// table does not hold, an `rd` write or a `next_pc` that is not what the
/// instruction computes — which the emulator cannot produce.
fn jump_branch_slt(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    let fam = family::JUMP_BRANCH_SLT;
    let traces = src.archive.family_traces();
    let trace = traces
        .family(fam)
        .ok_or("the archive has no JUMP_BRANCH_SLT buffer")?;
    let table = src
        .program
        .tables
        .family(fam)
        .ok_or("the program has no JUMP_BRANCH_SLT table")?;
    let h = src.height;
    let start = src.index as usize * h;
    let end = (start + h).min(trace.len());
    let cycles = &trace.cycle[start..end];
    let log = src.archive.memory_log();
    let queries = frame_queries(fam);
    let width = queries.len();

    let mut decoded: [Vec<u32>; 6] = Default::default();
    let mut kinds: [Vec<u32>; 12] = Default::default();
    // cmp_rhs rs1_hi rs1_sign cmp_rhs_hi cmp_rhs_sign lt cmp_gap cmp_gap_hi
    // eq taken jalr_drop pc_wrap next_pc_hi rd_hi, then rd_selected.
    let mut cells: [Vec<u32>; 15] = Default::default();
    let mut eq_inv = Vec::new();
    for r in start..end {
        let row = trace.row(r);
        let slot = row.pc as usize / 2;
        let field = |column: usize| {
            table.get(column, slot).unwrap_or_else(|| {
                panic!(
                    "cycle {} runs pc {:#x}, which the JUMP_BRANCH_SLT table does not hold",
                    row.cycle, row.pc
                )
            })
        };
        // lookup_tuple: pc next_pc rs1 rs2 rd imm extra_mask.
        let row_values = [field(1), field(2), field(3), field(4), field(5), field(6)];
        let (seq, imm, mask) = (row_values[0], row_values[4], row_values[5]);
        let bit = mask.trailing_zeros();
        let read = |role: Role| row.query(role).map_or(0, |q| q.read_value);
        let a = read(Role::Rs1);
        // An I-type comparison's absent rs2 reads 0, so its right operand is
        // the immediate; every other kind compares against rs2.
        let rhs = match bit {
            jbs::SLTI | jbs::SLTIU => read(Role::Rs2) + imm,
            _ => read(Role::Rs2),
        };
        let lt = match bit {
            jbs::SLTI | jbs::SLT | jbs::BLT | jbs::BGE => (a as i32) < (rhs as i32),
            _ => a < rhs,
        };
        let eq = a == rhs;
        let taken = match bit {
            jbs::BEQ => eq,
            jbs::BNE => !eq,
            jbs::BLT | jbs::BLTU => lt,
            jbs::BGE | jbs::BGEU => !lt,
            _ => false,
        };
        let (next, wrap, drop) = match bit {
            _ if bit == jbs::JAL || taken => {
                let (target, carry) = add(row.pc, imm);
                (target, carry, 0)
            }
            jbs::JALR => {
                let (sum, carry) = add(a, imm);
                (sum & !1, carry, sum & 1)
            }
            _ => (seq, 0, 0),
        };
        assert_eq!(
            row.next_pc, next,
            "cycle {}: the trace's next_pc is not the family's",
            row.cycle
        );
        let sel = match bit {
            jbs::JAL | jbs::JALR => seq,
            jbs::SLTI | jbs::SLTIU | jbs::SLT | jbs::SLTU => lt as u32,
            _ => 0,
        };
        if let Some(rd) = row.query(Role::Rd).filter(|q| q.addr != 0) {
            assert_eq!(
                rd.write_value, sel,
                "cycle {}: the trace's rd write is not what the instruction computes",
                row.cycle
            );
        }
        let gap = a.wrapping_sub(rhs);
        let values = [
            rhs,
            a >> 16,
            a >> 31,
            rhs >> 16,
            rhs >> 31,
            lt as u32,
            gap,
            gap >> 16,
            eq as u32,
            taken as u32,
            drop,
            wrap,
            next >> 16,
            sel >> 16,
            sel,
        ];
        for (column, v) in cells.iter_mut().zip(values) {
            column.push(v);
        }
        eq_inv.push(
            (Fr::from_u64(a as u64) - Fr::from_u64(rhs as u64))
                .inverse()
                .unwrap_or(Fr::ZERO),
        );
        for (column, v) in decoded.iter_mut().zip(row_values) {
            column.push(v);
        }
        for (k, column) in kinds.iter_mut().enumerate() {
            column.push((k as u32 == bit) as u32);
        }
    }

    let mut out = build_memory_columns(log, queries, cycles, h);
    for (address, column) in build_frame_witness(log, queries, cycles, h) {
        // The computed value, not S14's masked one.
        if address != rd_selected(width) {
            out.push((address, column));
        }
    }
    let [cmp_rhs, rs1_hi, rs1_sign, rhs_hi, rhs_sign, lt, gap, gap_hi, eq, taken, drop, wrap, next_hi, rd_hi, sel] =
        cells;
    out.push((rd_selected(width), u32_column(sel, h)));
    for (address, values) in jbs_circuit::DECODED.iter().zip(decoded) {
        out.push((*address, u32_column(values, h)));
    }
    for (address, values) in jbs_circuit::KINDS.iter().zip(kinds) {
        out.push((*address, u32_column(values, h)));
    }
    for (address, values) in [
        (jbs_circuit::CMP_RHS, cmp_rhs),
        (jbs_circuit::RS1_HI, rs1_hi),
        (jbs_circuit::RS1_SIGN, rs1_sign),
        (jbs_circuit::CMP_RHS_HI, rhs_hi),
        (jbs_circuit::CMP_RHS_SIGN, rhs_sign),
        (jbs_circuit::LT, lt),
        (jbs_circuit::CMP_GAP, gap),
        (jbs_circuit::CMP_GAP_HI, gap_hi),
        (jbs_circuit::EQ, eq),
        (jbs_circuit::TAKEN, taken),
        (jbs_circuit::JALR_DROP, drop),
        (jbs_circuit::PC_WRAP, wrap),
        (jbs_circuit::NEXT_PC_HI, next_hi),
        (jbs_circuit::RD_HI, rd_hi),
    ] {
        out.push((address, u32_column(values, h)));
    }
    eq_inv.resize(h, Fr::ZERO);
    out.push((
        jbs_circuit::EQ_INV,
        MultilinearPoly::new(PolyBacking::Fr(eq_inv)),
    ));
    for j in 0..jbs_circuit::TABLE_WIDTH {
        out.push((PolyAddress::Setup(j as u32), table.column_poly(j)));
    }
    let generic = generic_table(h.trailing_zeros());
    for (address, column) in jbs_circuit::GENERIC_TABLE.iter().zip(generic) {
        out.push((*address, column));
    }
    Ok(out)
}
