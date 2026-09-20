//! The family fills: how each family's trace buffer becomes its circuit's
//! committed columns. `docs/spec/shard-proof.md` §8.1 and §11.
//!
//! A fill returns every `M`, `W` and `S` column but the multiplicities, which
//! the common path counts over the family's channels.

use constants::extra_mask::add_sub_lui_auipc as kind;
use constants::extra_mask::jump_branch_slt as jbs;
use constants::extra_mask::mul_div as md;
use constants::extra_mask::shift_bitwise as sb;
use constants::extra_mask::system_code;
use constants::{ecall, family, memory};
use constraints::add_sub::{
    DECODED, IS_ECALL, IS_FENCE, KINDS, NEXT_PC_HI, PC_WRAP, RD_HI, TABLE_WIDTH, WRAP,
};
use constraints::jump_branch_slt as jbs_circuit;
use constraints::memory::{frame_queries, rd_selected};
use constraints::mul_div as md_circuit;
use constraints::shift_bitwise as sb_circuit;
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
        family::SHIFT_BITWISE => Some(shift_bitwise),
        family::MUL_DIV => Some(mul_div),
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

fn fr_column(mut values: Vec<Fr>, height: usize) -> MultilinearPoly {
    values.resize(height, Fr::ZERO);
    MultilinearPoly::new(PolyBacking::Fr(values))
}

/// A signed integer as a field element. Every value a fill hands to an `Fr`
/// column is a product or a sign-adjusted operand, so it fits an `i128` and is
/// far below the modulus either way.
fn signed(v: i128) -> Fr {
    let magnitude = |m: u128| {
        let shift = Fr::from_u64(1 << 32) * Fr::from_u64(1 << 32);
        Fr::from_u64((m >> 64) as u64) * shift + Fr::from_u64(m as u64)
    };
    match v < 0 {
        true => -magnitude(v.unsigned_abs()),
        false => magnitude(v as u128),
    }
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

/// A `SHIFT_BITWISE` shard, `docs/spec/shift-bitwise.md` §7: S14's frame
/// columns over the shard's cycles; the decoded row each cycle's pc claims and
/// its kind bits; the two half flags; `rs1`'s halfword and sign and the second
/// operand's halfword; the truncated shift amount with its powers and the bits
/// above it; the shared product with the sign-extension term, the overflow, the
/// residue and its scaling; both operands' bytes and their AND; the written
/// `rd` value over the frame's `rd_selected`, which S14's builder leaves 0 on an
/// `x0` write, and its high halfword; the family's decoded table as `S[0..7]`
/// and the packed generic table as `S[7..10]`.
///
/// Panics if the trace and the decoded table disagree — a cycle at a pc the
/// table does not hold, an `rd` write or a `next_pc` that is not what the
/// instruction computes, or a row carrying both a register `rs2` and an
/// immediate — which the emulator cannot produce.
fn shift_bitwise(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    let fam = family::SHIFT_BITWISE;
    let traces = src.archive.family_traces();
    let trace = traces
        .family(fam)
        .ok_or("the archive has no SHIFT_BITWISE buffer")?;
    let table = src
        .program
        .tables
        .family(fam)
        .ok_or("the program has no SHIFT_BITWISE table")?;
    let h = src.height;
    let start = src.index as usize * h;
    let end = (start + h).min(trace.len());
    let cycles = &trace.cycle[start..end];
    let log = src.archive.memory_log();
    let queries = frame_queries(fam);
    let width = queries.len();

    let mut decoded: [Vec<u32>; 6] = Default::default();
    let mut kinds: [Vec<u32>; 12] = Default::default();
    // f_shift f_bitwise rs1_hi rs1_sign src2_hi amount pow copow high high_hi
    // se ovf ovf_hi residue residue_hi scaled scaled_hi rd_hi, then rd_selected.
    let mut cells: [Vec<u32>; 19] = Default::default();
    let mut bytes: [Vec<u32>; 12] = Default::default();
    let (mut shift_in, mut shift_prod) = (Vec::new(), Vec::new());
    for r in start..end {
        let row = trace.row(r);
        let slot = row.pc as usize / 2;
        let field = |column: usize| {
            table.get(column, slot).unwrap_or_else(|| {
                panic!(
                    "cycle {} runs pc {:#x}, which the SHIFT_BITWISE table does not hold",
                    row.cycle, row.pc
                )
            })
        };
        // lookup_tuple: pc next_pc rs1 rs2 rd imm extra_mask.
        let row_values = [field(1), field(2), field(3), field(4), field(5), field(6)];
        let (fall, imm, mask) = (row_values[0], row_values[4], row_values[5]);
        let bit = mask.trailing_zeros();
        let read = |role: Role| row.query(role).map_or(0, |q| q.read_value);
        let (a, b) = (read(Role::Rs1), read(Role::Rs2));
        // One of the two addends is always zero — an I-type row makes no rs2
        // query and an R-type row's decoded immediate is 0 — which is what
        // makes `rs2 + imm` one expression for both operand shapes and keeps
        // the field sum a 32-bit word.
        assert!(
            b == 0 || imm == 0,
            "cycle {}: a SHIFT_BITWISE row carries both a register rs2 and an immediate",
            row.cycle
        );
        let src2 = b + imm;
        let amount = src2 & 31;
        let (pow, copow) = (1u32 << amount, 1u32 << (31 - amount));
        let is_shift = matches!(
            bit,
            sb::SLLI | sb::SRLI | sb::SRAI | sb::SLL | sb::SRL | sb::SRA
        );
        let is_arithmetic = matches!(bit, sb::SRAI | sb::SRA);
        let se = (is_arithmetic && a >> 31 == 1) as u32;
        let value = match bit {
            sb::SLLI | sb::SLL => a << amount,
            sb::SRLI | sb::SRL => a >> amount,
            sb::SRAI | sb::SRA => ((a as i32) >> amount) as u32,
            sb::ANDI | sb::AND => a & src2,
            sb::ORI | sb::OR => a | src2,
            sb::XORI | sb::XOR => a ^ src2,
            other => panic!("cycle {} has kind bit {other}", row.cycle),
        };
        // The one product: `rs1·2^s` on a left shift, `rd_adj·2^s` on a right
        // one, and nothing on a bitwise row, whose looked-up pair is zero.
        let word = 1i64 << 32;
        let (input, ovf, residue) = match bit {
            sb::SLLI | sb::SLL => {
                let product = a as i64 * pow as i64;
                (a as i64, (product >> 32) as u32, 0)
            }
            sb::SRLI | sb::SRL | sb::SRAI | sb::SRA => {
                let rd_adj = value as i64 - se as i64 * word;
                let rs1_adj = a as i64 - se as i64 * word;
                let residue = rs1_adj - rd_adj * pow as i64;
                assert!(
                    (0..pow as i64).contains(&residue),
                    "cycle {}: the shift's residue is not below its power",
                    row.cycle
                );
                (rd_adj, 0, residue as u32)
            }
            _ => (0, 0, 0),
        };
        let (pow, copow) = match is_shift {
            true => (pow, copow),
            // A bitwise row looks nothing up, and `pow·copow = 2^31·f_shift`
            // holds there only at zero.
            false => (0, 0),
        };
        let product = input * pow as i64;
        let scaled = 2 * residue as u64 * copow as u64;
        if let Some(rd) = row.query(Role::Rd).filter(|q| q.addr != 0) {
            assert_eq!(
                rd.write_value, value,
                "cycle {}: the trace's rd write is not what the instruction computes",
                row.cycle
            );
        }
        assert_eq!(
            row.next_pc, fall,
            "cycle {}: the trace's next_pc is not the decoded fall-through",
            row.cycle
        );
        let values = [
            is_shift as u32,
            !is_shift as u32,
            a >> 16,
            a >> 31,
            src2 >> 16,
            amount,
            pow,
            copow,
            src2 >> 5,
            (src2 >> 5) >> 16,
            se,
            ovf,
            ovf >> 16,
            residue,
            residue >> 16,
            scaled as u32,
            (scaled >> 16) as u32,
            value >> 16,
            value,
        ];
        for (column, v) in cells.iter_mut().zip(values) {
            column.push(v);
        }
        for j in 0..4 {
            let (byte_a, byte_b) = ((a >> (8 * j)) & 0xff, (src2 >> (8 * j)) & 0xff);
            bytes[j].push(byte_a);
            bytes[4 + j].push(byte_b);
            bytes[8 + j].push(byte_a & byte_b);
        }
        shift_in.push(signed(input as i128));
        shift_prod.push(signed(product as i128));
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
    let [f_shift, f_bitwise, rs1_hi, rs1_sign, src2_hi, amount, pow, copow, high, high_hi, se, ovf, ovf_hi, residue, residue_hi, scaled, scaled_hi, rd_hi, sel] =
        cells;
    out.push((rd_selected(width), u32_column(sel, h)));
    for (address, values) in sb_circuit::DECODED.iter().zip(decoded) {
        out.push((*address, u32_column(values, h)));
    }
    for (address, values) in sb_circuit::KINDS.iter().zip(kinds) {
        out.push((*address, u32_column(values, h)));
    }
    for (address, values) in [
        (sb_circuit::F_SHIFT, f_shift),
        (sb_circuit::F_BITWISE, f_bitwise),
        (sb_circuit::RS1_HI, rs1_hi),
        (sb_circuit::RS1_SIGN, rs1_sign),
        (sb_circuit::SRC2_HI, src2_hi),
        (sb_circuit::AMOUNT, amount),
        (sb_circuit::POW, pow),
        (sb_circuit::COPOW, copow),
        (sb_circuit::HIGH, high),
        (sb_circuit::HIGH_HI, high_hi),
        (sb_circuit::SE, se),
        (sb_circuit::OVF, ovf),
        (sb_circuit::OVF_HI, ovf_hi),
        (sb_circuit::RESIDUE, residue),
        (sb_circuit::RESIDUE_HI, residue_hi),
        (sb_circuit::SCALED, scaled),
        (sb_circuit::SCALED_HI, scaled_hi),
        (sb_circuit::RD_HI, rd_hi),
    ] {
        out.push((address, u32_column(values, h)));
    }
    let mut bytes = bytes.into_iter();
    for group in [
        sb_circuit::BYTES_A,
        sb_circuit::BYTES_B,
        sb_circuit::BYTES_AND,
    ] {
        for address in group {
            let values = bytes.next().expect("twelve byte columns");
            out.push((address, u32_column(values, h)));
        }
    }
    out.push((sb_circuit::SHIFT_IN, fr_column(shift_in, h)));
    out.push((sb_circuit::SHIFT_PROD, fr_column(shift_prod, h)));
    for j in 0..sb_circuit::TABLE_WIDTH {
        out.push((PolyAddress::Setup(j as u32), table.column_poly(j)));
    }
    let generic = generic_table(h.trailing_zeros());
    for (address, column) in sb_circuit::GENERIC_TABLE.iter().zip(generic) {
        out.push((*address, column));
    }
    Ok(out)
}

/// A `MUL_DIV` shard, `docs/spec/mul-div.md` §7: S14's frame columns over the
/// shard's cycles; the decoded row each cycle's pc claims — **five values, not
/// six**: this family's tuple has no immediate — and its kind bits; the
/// division flag; both operands' halfwords, top bits and sign adjustments; the
/// one product's multiplicands, its two halves and its sign; the division
/// witness with its two is-zero gadgets and the magnitude gap; the written `rd`
/// value over the frame's `rd_selected`, which S14's builder leaves 0 on an
/// `x0` write, and its high halfword; the family's decoded table as `S[0..6]`
/// and the packed generic table as `S[6..9]`.
///
/// Panics if the trace and the decoded table disagree — a cycle at a pc the
/// table does not hold, an `rd` write or a `next_pc` that is not what the
/// instruction computes — which the emulator cannot produce.
fn mul_div(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    let fam = family::MUL_DIV;
    let traces = src.archive.family_traces();
    let trace = traces
        .family(fam)
        .ok_or("the archive has no MUL_DIV buffer")?;
    let table = src
        .program
        .tables
        .family(fam)
        .ok_or("the program has no MUL_DIV table")?;
    let h = src.height;
    let start = src.index as usize * h;
    let end = (start + h).min(trace.len());
    let cycles = &trace.cycle[start..end];
    let log = src.archive.memory_log();
    let queries = frame_queries(fam);
    let width = queries.len();

    let mut decoded: [Vec<u32>; 5] = Default::default();
    let mut kinds: [Vec<u32>; 8] = Default::default();
    // f_div rs1_hi rs1_top rs2_hi rs2_top s1 s2 p_low p_low_hi p_high
    // p_high_hi p_sign q q_hi q_sign r r_hi r_sign rz d1 dz abs_r abs_d gap
    // gap_hi rd_hi, then rd_selected.
    let mut cells: [Vec<u32>; 27] = Default::default();
    let (mut mx_col, mut my_col) = (Vec::new(), Vec::new());
    let (mut r_inv_col, mut d_inv_col) = (Vec::new(), Vec::new());
    let word = 1i128 << 32;
    for row_index in start..end {
        let row = trace.row(row_index);
        let slot = row.pc as usize / 2;
        let field = |column: usize| {
            table.get(column, slot).unwrap_or_else(|| {
                panic!(
                    "cycle {} runs pc {:#x}, which the MUL_DIV table does not hold",
                    row.cycle, row.pc
                )
            })
        };
        // lookup_tuple: pc next_pc rs1 rs2 rd extra_mask — six columns.
        let row_values = [field(1), field(2), field(3), field(4), field(5)];
        let (fall, mask) = (row_values[0], row_values[4]);
        let bit = mask.trailing_zeros();
        let read = |role: Role| row.query(role).map_or(0, |q| q.read_value);
        let (a, b) = (read(Role::Rs1), read(Role::Rs2));

        // Each operand's sign adjustment: `mulhsu` is the asymmetric one, and
        // every unsigned position takes 0 whatever the operand's top bit.
        let lhs_signed = matches!(bit, md::MUL | md::MULH | md::MULHSU | md::DIV | md::REM);
        let rhs_signed = matches!(bit, md::MUL | md::MULH | md::DIV | md::REM);
        let s1 = (lhs_signed && a >> 31 == 1) as u32;
        let s2 = (rhs_signed && b >> 31 == 1) as u32;
        let rs1_adj = a as i128 - s1 as i128 * word;
        let rs2_adj = b as i128 - s2 as i128 * word;

        // The division witness, RV32M's exactly: a zero divisor gives a
        // quotient of all ones and the dividend back, and `−2^31 ÷ −1` gives
        // `−2^31` and 0, which `wrapping_div` and `wrapping_rem` are.
        let is_div = matches!(bit, md::DIV | md::DIVU | md::REM | md::REMU);
        let signed_div = matches!(bit, md::DIV | md::REM);
        let (q_word, r_word) = match (is_div, b, signed_div) {
            (false, _, _) => (0, 0),
            (true, 0, _) => (u32::MAX, a),
            (true, _, true) => (
                (a as i32).wrapping_div(b as i32) as u32,
                (a as i32).wrapping_rem(b as i32) as u32,
            ),
            (true, _, false) => (a / b, a % b),
        };
        let rz = (is_div && r_word == 0) as u32;
        let dz = (is_div && b == 0) as u32;
        let d1 = is_div as u32 * s1;
        // The remainder's sign is not its word's top bit: it is 1 exactly
        // where the dividend is negative and the remainder is not zero, which
        // is what makes the division truncated rather than floored.
        let r_sign = d1 * (1 - rz);
        let r_adj = r_word as i128 - r_sign as i128 * word;
        // On a zero divisor the identity says nothing about the quotient — the
        // pin fixes its word and leaves its sign free — and everywhere else
        // the identity determines it exactly.
        let q_adj = match (is_div, b) {
            (false, _) => 0,
            (true, 0) => q_word as i128,
            (true, _) => {
                let numerator = rs1_adj - r_adj;
                assert_eq!(
                    numerator % rs2_adj,
                    0,
                    "cycle {}: the division identity does not divide",
                    row.cycle
                );
                numerator / rs2_adj
            }
        };
        let q_sign = (q_adj < 0) as u32;
        assert_eq!(
            q_word as i128,
            q_adj + q_sign as i128 * word,
            "cycle {}: the quotient's word is not its adjusted value",
            row.cycle
        );

        // ONE product: the two operands on a multiply row, the divisor and the
        // quotient on a division one.
        let (mx, my) = match is_div {
            true => (rs2_adj, q_adj),
            false => (rs1_adj, rs2_adj),
        };
        let product = mx * my;
        let p_sign = (product < 0) as u32;
        let shifted = product + p_sign as i128 * (word * word);
        assert!(
            (0..word * word).contains(&shifted),
            "cycle {}: the product does not fit two words",
            row.cycle
        );
        let (p_low, p_high) = (shifted as u32, (shifted >> 32) as u32);

        let abs_r = r_adj.unsigned_abs() as u64;
        let abs_d = rs2_adj.unsigned_abs() as u64;
        let gap = match is_div {
            false => 0,
            true => abs_d + (dz as u64) * (1 << 32) - abs_r - 1,
        };
        let value = match bit {
            md::MUL => p_low,
            md::MULH | md::MULHSU | md::MULHU => p_high,
            md::DIV | md::DIVU => q_word,
            md::REM | md::REMU => r_word,
            other => panic!("cycle {} has kind bit {other}", row.cycle),
        };
        if let Some(rd) = row.query(Role::Rd).filter(|q| q.addr != 0) {
            assert_eq!(
                rd.write_value, value,
                "cycle {}: the trace's rd write is not what the instruction computes",
                row.cycle
            );
        }
        assert_eq!(
            row.next_pc, fall,
            "cycle {}: the trace's next_pc is not the decoded fall-through",
            row.cycle
        );
        let values = [
            is_div as u32,
            a >> 16,
            a >> 31,
            b >> 16,
            b >> 31,
            s1,
            s2,
            p_low,
            p_low >> 16,
            p_high,
            p_high >> 16,
            p_sign,
            q_word,
            q_word >> 16,
            q_sign,
            r_word,
            r_word >> 16,
            r_sign,
            rz,
            d1,
            dz,
            abs_r as u32,
            abs_d as u32,
            gap as u32,
            (gap >> 16) as u32,
            value >> 16,
            value,
        ];
        for (column, v) in cells.iter_mut().zip(values) {
            column.push(v);
        }
        mx_col.push(signed(mx));
        my_col.push(signed(my));
        let unit = |on: bool, x: u32| match on {
            true => Fr::from_u64(x as u64).inverse().unwrap_or(Fr::ZERO),
            false => Fr::ZERO,
        };
        r_inv_col.push(unit(is_div, r_word));
        d_inv_col.push(unit(is_div, b));
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
    let [f_div, rs1_hi, rs1_top, rs2_hi, rs2_top, s1, s2, p_low, p_low_hi, p_high, p_high_hi, p_sign, q, q_hi, q_sign, r, r_hi, r_sign, rz, d1, dz, abs_r, abs_d, gap, gap_hi, rd_hi, sel] =
        cells;
    out.push((rd_selected(width), u32_column(sel, h)));
    for (address, values) in md_circuit::DECODED.iter().zip(decoded) {
        out.push((*address, u32_column(values, h)));
    }
    for (address, values) in md_circuit::KINDS.iter().zip(kinds) {
        out.push((*address, u32_column(values, h)));
    }
    for (address, values) in [
        (md_circuit::F_DIV, f_div),
        (md_circuit::RS1_HI, rs1_hi),
        (md_circuit::RS1_TOP, rs1_top),
        (md_circuit::RS2_HI, rs2_hi),
        (md_circuit::RS2_TOP, rs2_top),
        (md_circuit::S1, s1),
        (md_circuit::S2, s2),
        (md_circuit::P_LOW, p_low),
        (md_circuit::P_LOW_HI, p_low_hi),
        (md_circuit::P_HIGH, p_high),
        (md_circuit::P_HIGH_HI, p_high_hi),
        (md_circuit::P_SIGN, p_sign),
        (md_circuit::Q, q),
        (md_circuit::Q_HI, q_hi),
        (md_circuit::Q_SIGN, q_sign),
        (md_circuit::R, r),
        (md_circuit::R_HI, r_hi),
        (md_circuit::R_SIGN, r_sign),
        (md_circuit::RZ, rz),
        (md_circuit::D1, d1),
        (md_circuit::DZ, dz),
        (md_circuit::ABS_R, abs_r),
        (md_circuit::ABS_D, abs_d),
        (md_circuit::GAP, gap),
        (md_circuit::GAP_HI, gap_hi),
        (md_circuit::RD_HI, rd_hi),
    ] {
        out.push((address, u32_column(values, h)));
    }
    for (address, values) in [
        (md_circuit::MX, mx_col),
        (md_circuit::MY, my_col),
        (md_circuit::R_INV, r_inv_col),
        (md_circuit::D_INV, d_inv_col),
    ] {
        out.push((address, fr_column(values, h)));
    }
    for j in 0..md_circuit::TABLE_WIDTH {
        out.push((PolyAddress::Setup(j as u32), table.column_poly(j)));
    }
    let generic = generic_table(h.trailing_zeros());
    for (address, column) in md_circuit::GENERIC_TABLE.iter().zip(generic) {
        out.push((*address, column));
    }
    Ok(out)
}
