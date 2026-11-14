//! The `JUMP_BRANCH_SLT` family's circuit: `jal`, `jalr`, the six branches,
//! `slt`, `sltu`, `slti` and `sltiu`, over 64-bit registers.
//!
//! `docs/spec/jump-branch-slt.md` specifies it: the columns, the gates, the
//! lookups and the argument. This file is that page as data, on
//! `crate::family`'s builder with its 64-bit comparison and
//! `crate::gadgets::is_zero`.

use alloc::vec::Vec;

use constants::extra_mask::jump_branch_slt as kind;
use constants::family;

use crate::family::{sum, Expr, Family, Imm, T16, T32};
use crate::gadgets::is_zero;
use crate::lookup::{check_copowers, ChannelSpec};
use crate::memory::{RD, RS1, RS2};
use crate::{CircuitArtifact, Coeff};

/// The kinds, in `constants::extra_mask::jump_branch_slt` order.
pub const KINDS: [&str; 12] = [
    "slti", "sltiu", "slt", "sltu", "beq", "bne", "blt", "bge", "bltu", "bgeu", "jalr", "jal",
];

fn spec() -> Family {
    let mut f = Family::new(family::JUMP_BRANCH_SLT, &KINDS, Imm::Signed);
    let b = |j: u32| f.kinds[j as usize];
    let (slti, sltiu, slt, sltu) = (b(kind::SLTI), b(kind::SLTIU), b(kind::SLT), b(kind::SLTU));
    let (beq, bne, blt, bge) = (b(kind::BEQ), b(kind::BNE), b(kind::BLT), b(kind::BGE));
    let (bltu, bgeu, jalr, jal) = (b(kind::BLTU), b(kind::BGEU), b(kind::JALR), b(kind::JAL));
    let (imm, neg, seq) = (f.imm.expect("an imm"), f.neg.expect("a signed imm"), f.seq);
    let (v1, v2, vh1, vh2) = (f.v(RS1), f.v(RS2), f.vh(RS1), f.vh(RS2));
    let (pc, next_pc, sel, live) = (f.pc(), f.next_pc(), f.sel(), f.live());
    let ones = T32 - 1;

    let branches = [beq, bne, blt, bge, bltu, bgeu];
    let all = sum(&f.kinds.clone());
    f.mask_rule(RS1, all.clone() - jal);
    f.mask_rule(RS2, sum(&branches) + slt + sltu);
    f.mask_rule(RD, sum(&[slti, sltiu, slt, sltu, jalr, jal]));
    let (d1, d2, dd) = (f.rs1, f.rs2, f.rd);
    f.addr_rule(RS1, d1.into());
    f.addr_rule(RS2, d2.into());
    f.addr_rule(RD, dd.into());
    f.value_masked(RS1);
    f.value_masked(RS2);

    // The right operand: rs2, or the sign-extended immediate of an `slti` or
    // `sltiu` — one addend is always 0, so the sum needs no carry.
    let imm_cmp = sum(&[slti, sltiu]);
    let rhs_lo = f.col("cmp_rhs_lo");
    let rhs_hi = f.col("cmp_rhs_hi");
    f.gate("cmp_rhs_lo_rule", rhs_lo - v2 - imm_cmp.clone() * imm);
    f.gate(
        "cmp_rhs_hi_rule",
        Expr::from(rhs_hi) - vh2 - imm_cmp * neg * ones,
    );
    let signed = sum(&[slti, slt, blt, bge]);
    let (lt, gap_lo, gap_hi) =
        f.compare64("cmp", (v1.into(), vh1), (rhs_lo.into(), rhs_hi), signed);
    // eq = [rs1 = cmp_rhs] on a live row: both gap words are 0 exactly there.
    let eq = f.col("eq");
    let eq_inv = f.col("eq_inv");
    let one = Coeff::Literal(field::Fp::ONE);
    let [inverse, at_nonzero] = is_zero(&[(one, gap_lo), (one, gap_hi)], eq_inv, eq, live);
    f.push_gate("eq_inverse", inverse);
    f.push_gate("eq_at_nonzero", at_nonzero);

    let taken = f.bit("taken");
    let w1 = sum(&[bne, bge, bgeu]);
    let w_eq = Expr::from(beq) - bne;
    let w_lt = sum(&[blt, bltu]) - bge - bgeu;
    f.gate("taken_rule", Expr::from(taken) - w1 - w_eq * eq - w_lt * lt);

    // next_pc + 2^32·pc_wrap is the fall-through, pc + imm or rs1 + imm with
    // bit 0 dropped; a `jalr` target's high word, rs1's plus the immediate's
    // and the carry, must vanish mod 2^32: no pc is at or above 2^32.
    let jalr_drop = f.bit("jalr_drop");
    let pc_wrap = f.bit("pc_wrap");
    let hi_wrap = f.bit("hi_wrap");
    let rel = Expr::from(taken) + jal;
    f.gate(
        "next_pc_rule",
        next_pc + pc_wrap * T32 - seq + (rel.clone() + jalr) * seq
            - rel * (pc + imm)
            - jalr * (v1 + imm - jalr_drop),
    );
    f.gate(
        "jalr_hi",
        jalr * (vh1 + pc_wrap - hi_wrap * T32) + jalr * neg * ones,
    );
    f.gate(
        "rd_value_rule",
        Expr::from(sel) - sum(&[jal, jalr]) * seq - sum(&[slti, sltiu, slt, sltu]) * lt,
    );
    let sel_hi = f.sel_hi();
    f.gate("rd_hi_zero", sel_hi.into());
    f.word("rd", sel.into());
    // next_pc is a word and even: its low halfword halved is in range only
    // where it is even, keeping the family off HALT_PC (docs/spec/memory.md §5).
    let next_hi = f.word("next_pc", next_pc.into());
    let half = field::Fp::from_u64(2).inverse().expect("2 is a unit");
    f.range16(
        "next_pc_even",
        Expr::from(next_pc) * half - next_hi * (T16 / 2),
        live,
    );
    f
}

/// The family's circuit over `2^trace_vars` rows,
/// `docs/spec/jump-branch-slt.md`. Panics on every refusal of the assembly and
/// if `next_pc`, which `next_pc_even` scales, lacks its direct bound.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    let f = spec();
    let (next_pc, live) = (f.next_pc(), f.live());
    let a = f.artifact(trace_vars);
    if let Err(e) = check_copowers(&a, &[(next_pc, live)]) {
        panic!("jump_branch_slt: {e}");
    }
    a
}

/// The family's channels, in output order.
pub fn channels() -> Vec<ChannelSpec> {
    spec().channels()
}
