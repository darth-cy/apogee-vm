//! The `MUL_DIV` family's circuit: the M extension and its W forms, and every
//! shift — a product, or a floor quotient, by a looked-up `2^s` — on one
//! 64×64 core over 16-bit limbs.
//!
//! `docs/spec/mul-div.md` specifies it. A row proves `q·B + r = Z` modulo
//! `2^128`, two's complement, over four 32-bit chunks with bounded carries: a
//! multiply-like row has `q = A`, `r = 0` and `Z` its product words; a
//! divide-like row has `Z = A` and `q`, `r` its quotient and remainder, the
//! remainder's sign and magnitude bounded so the quotient is the ISA's. Every
//! chunk's total stays below `2^52`, so each identity holds over the
//! integers at `p = 2^64 − 59`.

use alloc::format;
use alloc::vec::Vec;

use constants::extra_mask::mul_div as kind;
use constants::{family, generic_table};

use crate::family::{k, sum, Expr, Family, Imm, T16, T32};
use crate::gadgets::is_zero;
use crate::lookup::ChannelSpec;
use crate::memory::{RD, RS1, RS2};
use crate::{CircuitArtifact, Coeff, PolyAddress};

/// The kinds, in `constants::extra_mask::mul_div` order.
pub const KINDS: [&str; 25] = [
    "mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu", "mulw", "divw", "divuw",
    "remw", "remuw", "slli", "srli", "srai", "slliw", "srliw", "sraiw", "sll", "srl", "sra",
    "sllw", "srlw", "sraw",
];

use kind::*;

/// Divide-like: `Z = A`, and `q`, `r` the quotient and remainder.
const DIVIDE: [u32; 16] = [
    DIV, DIVU, REM, REMU, DIVW, DIVUW, REMW, REMUW, SRLI, SRAI, SRLIW, SRAIW, SRL, SRA, SRLW, SRAW,
];
/// The 32-bit forms, which write their low word sign-extended.
const WORD: [u32; 11] = [
    MULW, DIVW, DIVUW, REMW, REMUW, SLLIW, SRLIW, SRAIW, SLLW, SRLW, SRAW,
];
/// Every shift: `B = 2^s` from the generic table.
const SHIFT_64: [u32; 6] = [SLLI, SRLI, SRAI, SLL, SRL, SRA];
const SHIFT_W: [u32; 6] = [SLLIW, SRLIW, SRAIW, SLLW, SRLW, SRAW];
/// The shifts that read no `rs2`.
const SHIFT_IMM: [u32; 6] = [SLLI, SRLI, SRAI, SLLIW, SRLIW, SRAIW];
/// `A` read signed, its sign `rs1`'s bit 63 or, for a W form, bit 31.
const SIGNED_A_64: [u32; 6] = [MULH, MULHSU, DIV, REM, SRAI, SRA];
const SIGNED_A_W: [u32; 4] = [DIVW, REMW, SRAIW, SRAW];
/// `B` read signed.
const SIGNED_B_64: [u32; 3] = [MULH, DIV, REM];
const SIGNED_B_W: [u32; 2] = [DIVW, REMW];
/// `B = rs2`, 64 bits of it.
const RS2_64: [u32; 8] = [MUL, MULH, MULHSU, MULHU, DIV, DIVU, REM, REMU];
/// Truncated division: a nonzero remainder takes the dividend's sign.
const TRUNCATED: [u32; 4] = [DIV, REM, DIVW, REMW];
/// An unsigned quotient, never negative.
const UNSIGNED_Q: [u32; 8] = [DIVU, REMU, DIVUW, REMUW, SRLI, SRL, SRLIW, SRLW];
/// Where `rd` comes from.
const FROM_Z0: [u32; 6] = [MUL, SLLI, SLL, MULW, SLLIW, SLLW];
const FROM_Z2: [u32; 3] = [MULH, MULHSU, MULHU];
const FROM_Q: [u32; 12] = [
    DIV, DIVU, SRLI, SRAI, SRL, SRA, DIVW, DIVUW, SRLIW, SRAIW, SRLW, SRAW,
];
const FROM_R: [u32; 4] = [REM, REMU, REMW, REMUW];

/// A word as two 16-bit limbs over its column and its high halfword.
fn limbs(word: PolyAddress, h16: PolyAddress) -> [Expr; 2] {
    [word - h16 * T16, h16.into()]
}

fn spec() -> Family {
    let mut f = Family::new(family::MUL_DIV, &KINDS, Imm::Unsigned);
    let kinds = f.kinds.clone();
    let b =
        |list: &[u32]| -> Vec<PolyAddress> { list.iter().map(|j| kinds[*j as usize]).collect() };
    let any = |list: &[u32]| sum(&b(list));
    let (imm, seq) = (f.imm.expect("an imm"), f.seq);
    let (v1, v2, vh1, vh2) = (f.v(RS1), f.v(RS2), f.vh(RS1), f.vh(RS2));
    let (sel, sel_hi, live, next_pc) = (f.sel(), f.sel_hi(), f.live(), f.next_pc());
    let ones = T32 - 1;
    let all: Vec<u32> = (0..KINDS.len() as u32).collect();
    let wide: Vec<u32> = all.iter().copied().filter(|j| !WORD.contains(j)).collect();

    f.mask_rule(RS1, any(&all));
    f.mask_rule(RS2, any(&all) - any(&SHIFT_IMM));
    f.mask_rule(RD, any(&all));
    let (d1, d2, dd) = (f.rs1, f.rs2, f.rd);
    f.addr_rule(RS1, d1.into());
    f.addr_rule(RS2, d2.into());
    f.addr_rule(RD, dd.into());
    f.value_masked(RS1);
    f.value_masked(RS2);
    f.gate("next_pc_rule", next_pc - seq);

    let f_div = f.bit("f_div");
    let f_shift = f.bit("f_shift");
    f.gate("f_div_rule", f_div - any(&DIVIDE));
    let shifts: Vec<u32> = SHIFT_64.iter().chain(&SHIFT_W).copied().collect();
    f.gate("f_shift_rule", f_shift - any(&shifts));

    // The operands. A: rs1, or a W form's low word extended by its sign or 0.
    let (_, s1l) = f.signed_word("rs1_lo", v1.into());
    let (_, s1h) = f.signed_word("rs1_hi", vh1.into());
    let a_h = f.col("a_hi");
    let s_a = f.col("a_sign");
    f.gate(
        "a_hi_rule",
        a_h - any(&wide) * vh1 - any(&SIGNED_A_W) * s1l * ones,
    );
    f.gate(
        "a_sign_rule",
        s_a - any(&SIGNED_A_64) * s1h - any(&SIGNED_A_W) * s1l,
    );
    // The shift amount: rs2 + imm = 64·high + 32·tw + amt, where amt is the
    // power's key — below 64, or below 32 under POW_W's tag — and tw is the
    // bit a W shift ignores.
    let high = f.col("amount_high");
    f.word("amount_high", high.into());
    let tw = f.bit("amount_w");
    let amt = f.col("amount");
    f.gate("amount_split", v2 + imm - high * 64 - tw * 32 - amt);
    f.gate("amount_w_rule", any(&SHIFT_64) * tw);
    let p_lo = f.col("pow_lo");
    let p_hi = f.col("pow_hi");
    let tag =
        any(&SHIFT_64) * generic_table::POW as u64 + any(&SHIFT_W) * generic_table::POW_W as u64;
    f.generic("pow", tag, [Some(amt), Some(p_lo), Some(p_hi)], f_shift);
    // B: rs2, a W form's sign- or zero-extended low word, or the power.
    let b_l = f.col("b_lo");
    let b_h = f.col("b_hi");
    let (b_l_h, sbl) = f.signed_word("b_lo", b_l.into());
    let (b_h_h, sbh) = f.signed_word("b_hi", b_h.into());
    f.gate("b_lo_rule", b_l - v2 + f_shift * v2 - f_shift * p_lo);
    f.gate(
        "b_hi_rule",
        b_h - any(&RS2_64) * vh2 - any(&SIGNED_B_W) * sbl * ones - f_shift * p_hi,
    );
    let s_b = f.col("b_sign");
    f.gate(
        "b_sign_rule",
        s_b - any(&SIGNED_B_64) * sbh - any(&SIGNED_B_W) * sbl,
    );

    // q and r, and the product words.
    let q_l = f.col("q_lo");
    let q_h = f.col("q_hi");
    let q_l_h = f.word("q_lo", q_l.into());
    let q_h_h = f.word("q_hi", q_h.into());
    let s_q = f.bit("q_sign");
    let r_l = f.col("r_lo");
    let r_h = f.col("r_hi");
    let r_l_h = f.word("r_lo", r_l.into());
    f.word("r_hi", r_h.into());
    let s_r = f.bit("r_sign");
    let z: Vec<PolyAddress> = (0..4).map(|j| f.col(&format!("z{j}"))).collect();
    let z_h: Vec<PolyAddress> = (0..4)
        .map(|j| f.word(&format!("z{j}"), z[j].into()))
        .collect();

    // A multiply-like row: q = A, r = 0.
    let mul = Expr::from(live) - f_div;
    f.gate("q_lo_is_a", mul.clone() * (q_l - v1));
    f.gate("q_hi_is_a", mul.clone() * (q_h - a_h));
    f.gate("q_sign_is_a", mul.clone() * (s_q - s_a));
    f.gate("r_zero_on_multiply", mul * (r_l + r_h));
    f.gate("q_sign_unsigned", any(&UNSIGNED_Q) * s_q);

    // q·B + r = Z mod 2^128, two's complement: 16-bit limb products summed into
    // 32-bit chunks, the signs' corrections in the top two, a carry each.
    let q = [limbs(q_l, q_l_h), limbs(q_h, q_h_h)].concat();
    let bb = [limbs(b_l, b_l_h), limbs(b_h, b_h_h)].concat();
    let s = |m: usize| {
        (0..4)
            .filter(|i| m >= *i && m - i < 4)
            .fold(Expr::default(), |acc, i| {
                acc + q[i].clone() * bb[m - i].clone()
            })
    };
    let c: Vec<PolyAddress> = (0..4).map(|j| f.col(&format!("carry{j}"))).collect();
    let rhs = |zj: PolyAddress, a: Expr| Expr::from(zj) - f_div * zj + a;
    let a_fill = f_div * s_a * ones;
    f.gate(
        "chunk0",
        s(0) + s(1) * T16 + r_l - rhs(z[0], f_div * v1) - c[0] * T32,
    );
    f.gate(
        "chunk1",
        s(2) + s(3) * T16 + r_h + c[0] - rhs(z[1], f_div * a_h) - c[1] * T32,
    );
    f.gate(
        "chunk2",
        s(4) + s(5) * T16 + s_r * ones - s_q * b_l - s_b * q_l + c[1]
            - rhs(z[2], a_fill.clone())
            - c[2] * T32,
    );
    f.gate(
        "chunk3",
        s(6) + s_r * ones - s_q * b_h - s_b * q_h + c[2] - rhs(z[3], a_fill) - c[3] * T32,
    );
    f.range19("carry0_range", c[0].into(), live);
    f.range19("carry1_range", c[1].into(), live);
    f.range19("carry2_range", c[2] + k(3), live);
    f.range19("carry3_range", c[3] + k(3), live);

    // The division: r takes the dividend's sign unless it is 0 (truncation, not
    // floor), and |r| < |B| unless B = 0, which pins q to all ones.
    let one = Coeff::Literal(field::Fp::ONE);
    let r_inv = f.col("r_inv");
    let rz = f.col("r_is_zero");
    let [inverse, at_nonzero] = is_zero(&[(one, r_l), (one, r_h)], r_inv, rz, f_div);
    f.push_gate("r_is_zero_inverse", inverse);
    f.push_gate("r_is_zero_at_nonzero", at_nonzero);
    let d1 = f.col("dividend_signed");
    f.gate("dividend_signed_rule", d1 - any(&TRUNCATED) * s_a);
    f.gate("r_sign_rule", s_r - d1 + d1 * rz);
    let d_inv = f.col("b_inv");
    let dz = f.col("b_is_zero");
    let [inverse, at_nonzero] = is_zero(&[(one, b_l), (one, b_h)], d_inv, dz, f_div);
    f.push_gate("b_is_zero_inverse", inverse);
    f.push_gate("b_is_zero_at_nonzero", at_nonzero);
    f.gate("zero_divisor_q_lo", dz * q_l - dz * ones);
    f.gate("zero_divisor_q_hi", dz * q_h - dz * ones);
    // |B_s| − |r_s| − f_div + 2^64·dz, a 64-bit word: on a division row it is
    // the bound, on a multiply row |B_s| itself.
    let g_l = f.col("bound_lo");
    let g_h = f.col("bound_hi");
    f.word("bound_lo", g_l.into());
    f.word("bound_hi", g_h.into());
    let w = f.col("bound_carry");
    f.gate(
        "bound_lo_rule",
        Expr::from(b_l) - s_b * b_l * 2 - r_l + s_r * r_l * 2 - f_div - g_l - w * T32,
    );
    f.gate(
        "bound_hi_rule",
        Expr::from(b_h) - s_b * b_h * 2 - r_h + s_r * r_h * 2 + w + s_b * T32 - s_r * T32
            + dz * T32
            - g_h,
    );
    f.range19("bound_carry_range", w + k(3), live);

    // rd: the product's low or high words, q or r; a W form's low word with its
    // sign extended.
    let rd_h = f.col("rd_lo_h16");
    let rd_sign = f.col("rd_sign");
    f.gate(
        "rd_lo_h16_rule",
        Expr::from(rd_h)
            - any(&FROM_Z0) * z_h[0]
            - any(&FROM_Z2) * z_h[2]
            - any(&FROM_Q) * q_l_h
            - any(&FROM_R) * r_l_h,
    );
    f.generic(
        "rd_get_sign",
        k(generic_table::SIGN as u64),
        [Some(rd_h), Some(rd_sign), None],
        live,
    );
    f.gate(
        "rd_lo_rule",
        Expr::from(sel)
            - any(&FROM_Z0) * z[0]
            - any(&FROM_Z2) * z[2]
            - any(&FROM_Q) * q_l
            - any(&FROM_R) * r_l,
    );
    let z1_64: Vec<u32> = FROM_Z0
        .iter()
        .copied()
        .filter(|j| !WORD.contains(j))
        .collect();
    let q_64: Vec<u32> = FROM_Q
        .iter()
        .copied()
        .filter(|j| !WORD.contains(j))
        .collect();
    let r_64: Vec<u32> = FROM_R
        .iter()
        .copied()
        .filter(|j| !WORD.contains(j))
        .collect();
    f.gate(
        "rd_hi_rule",
        Expr::from(sel_hi)
            - any(&z1_64) * z[1]
            - any(&FROM_Z2) * z[3]
            - any(&q_64) * q_h
            - any(&r_64) * r_h
            - any(&WORD) * rd_sign * ones,
    );
    f
}

/// The family's circuit over `2^trace_vars` rows, `docs/spec/mul-div.md`.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    spec().artifact(trace_vars)
}

/// The family's channels, in output order.
pub fn channels() -> Vec<ChannelSpec> {
    spec().channels()
}
