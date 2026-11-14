//! The `ATOMICS` family's circuit: `lr`, `sc` and the nine AMOs, each in `.w`
//! and `.d`, one read-modify-write a row.
//!
//! `docs/spec/memory-ops.md` §6 specifies it. RAM is 32-bit words: the frame's
//! `ram` query is the word at the address, read and rewritten at slot 3, and a
//! `.d` form's high word is its `load` query at slot 2. One 64-bit comparison,
//! one 64-bit addition and eight AND bytes serve both widths, a `.w` form's
//! operands being its words extended — by their signs for `amomin.w` and
//! `amomax.w`, by 0 otherwise — and only its low word stored.

use alloc::format;
use alloc::vec::Vec;

use constants::extra_mask::atomics as kind;
use constants::{family, generic_table};

use crate::family::{k, sum, Expr, Family, Imm, T32};
use crate::lookup::{check_copowers, ChannelSpec};
use crate::memory::{LOAD, RAM, RD, RS1, RS2};
use crate::{CircuitArtifact, PolyAddress};

/// The kinds, in `constants::extra_mask::atomics` order: the `.w` forms, then
/// the `.d` forms, `kind::DOUBLE` above them.
pub const KINDS: [&str; 22] = [
    "amoadd_w",
    "amoswap_w",
    "lr_w",
    "sc_w",
    "amoxor_w",
    "amoor_w",
    "amoand_w",
    "amomin_w",
    "amomax_w",
    "amominu_w",
    "amomaxu_w",
    "amoadd_d",
    "amoswap_d",
    "lr_d",
    "sc_d",
    "amoxor_d",
    "amoor_d",
    "amoand_d",
    "amomin_d",
    "amomax_d",
    "amominu_d",
    "amomaxu_d",
];

/// `Σ_j 2^(8j)·bytes[j]`.
fn packed(bytes: &[PolyAddress]) -> Expr {
    bytes
        .iter()
        .enumerate()
        .fold(Expr::default(), |acc, (j, x)| acc + *x * (1u64 << (8 * j)))
}

fn spec() -> Family {
    let mut f = Family::new(family::ATOMICS, &KINDS, Imm::None);
    let kinds = f.kinds.clone();
    let w = |op: u32| kinds[op as usize];
    let d = |op: u32| kinds[(op + kind::DOUBLE) as usize];
    let both = |op: u32| Expr::from(w(op)) + d(op);
    let double = sum(&kinds[kind::DOUBLE as usize..]);
    let word = sum(&kinds[..kind::DOUBLE as usize]);
    let ones = T32 - 1;
    let (v1, vh1, v2, vh2, live) = (f.v(RS1), f.vh(RS1), f.v(RS2), f.vh(RS2), f.live());
    let (old, old_hi, new, new_hi) = (f.v(RAM), f.v(LOAD), f.wv(RAM), f.wv(LOAD));
    let (sel, sel_hi) = (f.sel(), f.sel_hi());

    let all = sum(&kinds);
    f.mask_rule(RS1, all.clone());
    f.mask_rule(RS2, all.clone() - w(kind::LR_W) - d(kind::LR_W));
    f.mask_rule(LOAD, double.clone());
    f.mask_rule(RAM, all.clone());
    f.mask_rule(RD, all.clone());
    let (d1, d2, dd) = (f.rs1, f.rs2, f.rd);
    f.addr_rule(RS1, d1.into());
    f.addr_rule(RS2, d2.into());
    f.addr_rule(RD, dd.into());
    f.value_masked(RS1);
    f.value_masked(RS2);
    f.value_masked(LOAD);
    let (seq, next_pc) = (f.seq, f.next_pc());
    f.gate("next_pc_rule", next_pc - seq);

    // The address is rs1, 8·dw + 4·bit2 below 2^32, a `.d` form's 8-aligned.
    let dw = f.col("dword_index");
    let bit2 = f.bit("bit2");
    f.gate("addr_word", v1 - dw * 8 - bit2 * 4);
    f.gate("addr_hi", vh1.into());
    f.gate("dword_aligned", double.clone() * bit2);
    let dw_h = f.word("dword_index", dw.into());
    f.range16("dword_index_hi_scaled", dw_h * 8, live);
    let at = dw * 8 + bit2 * 4;
    f.addr_rule(RAM, at.clone());
    f.addr_rule(LOAD, at + k(4));

    // The operands as 64-bit values: old = (old, old_hi), src = (rs2, src_hi),
    // a `.w` form's high words its signs' fill on amomin.w and amomax.w.
    let signed_w = Expr::from(w(kind::AMOMIN_W)) + w(kind::AMOMAX_W);
    let (_, old_sign) = f.signed_word("old_lo", old.into());
    let (_, src_sign) = f.signed_word("src_lo", v2.into());
    let lhs_hi = f.col("lhs_hi");
    let rhs_hi = f.col("rhs_hi");
    f.gate(
        "lhs_hi_rule",
        lhs_hi - old_hi - signed_w.clone() * old_sign * ones,
    );
    f.gate(
        "rhs_hi_rule",
        Expr::from(rhs_hi) - double.clone() * vh2 - signed_w * src_sign * ones,
    );
    let signed = both(kind::AMOMIN_W) + both(kind::AMOMAX_W);
    let (lt, _, _) = f.compare64("cmp", (old.into(), lhs_hi), (v2.into(), rhs_hi), signed);
    let min_lo = f.col("min_lo");
    let min_hi = f.col("min_hi");
    f.gate("min_lo_rule", min_lo - v2 - lt * (old - v2));
    f.gate("min_hi_rule", min_hi - rhs_hi - lt * (lhs_hi - rhs_hi));

    // old + src, 64 bits with two carries.
    let sum_lo = f.col("sum_lo");
    let sum_hi = f.col("sum_hi");
    let c0 = f.bit("add_carry_lo");
    let c1 = f.bit("add_carry_hi");
    f.gate("add_lo", old + v2 - sum_lo - c0 * T32);
    f.gate("add_hi", old_hi + rhs_hi + c0 - sum_hi - c1 * T32);
    f.word("sum_lo", sum_lo.into());
    f.word("sum_hi", sum_hi.into());

    // AND, OR and XOR over eight bytes each of old and src.
    let f_bitwise = f.bit("f_bitwise");
    f.gate(
        "f_bitwise_rule",
        f_bitwise - both(kind::AMOAND_W) - both(kind::AMOOR_W) - both(kind::AMOXOR_W),
    );
    let a: Vec<PolyAddress> = (0..8).map(|j| f.col(&format!("byte_a{j}"))).collect();
    let b: Vec<PolyAddress> = (0..8).map(|j| f.col(&format!("byte_b{j}"))).collect();
    let n: Vec<PolyAddress> = (0..8).map(|j| f.col(&format!("byte_and{j}"))).collect();
    for j in 0..8 {
        f.generic(
            &format!("and_byte_{j}"),
            k(generic_table::AND as u64),
            [Some(a[j]), Some(b[j]), Some(n[j])],
            f_bitwise,
        );
    }
    f.gate("old_lo_bytes", old - packed(&a[..4]));
    f.gate("old_hi_bytes", old_hi - packed(&a[4..]));
    f.gate("src_lo_bytes", v2 - packed(&b[..4]));
    f.gate("src_hi_bytes", rhs_hi - packed(&b[4..]));

    // The word each op writes, per word: `ops` names its kinds, `old` and `src`
    // its operands, `sum`, `and`, `min` the computed values.
    let written = |ops: &dyn Fn(u32) -> Expr,
                   (old, src, sm, and, min): (
        PolyAddress,
        PolyAddress,
        PolyAddress,
        Expr,
        PolyAddress,
    )| {
        ops(kind::LR_W) * old
            + (ops(kind::SC_W) + ops(kind::AMOSWAP_W)) * src
            + ops(kind::AMOADD_W) * sm
            + ops(kind::AMOAND_W) * and.clone()
            + ops(kind::AMOOR_W) * (old + src - and.clone())
            + ops(kind::AMOXOR_W) * (old + src - and * 2)
            + (ops(kind::AMOMIN_W) + ops(kind::AMOMINU_W)) * min
            + (ops(kind::AMOMAX_W) + ops(kind::AMOMAXU_W)) * (old + src - min)
    };
    let lo = written(&both, (old, v2, sum_lo, packed(&n[..4]), min_lo));
    f.gate("ram_value_rule", Expr::from(new) - lo);
    let dd = |op: u32| Expr::from(d(op));
    let hi = written(&dd, (old_hi, vh2, sum_hi, packed(&n[4..]), min_hi));
    f.gate("load_value_rule", Expr::from(new_hi) - hi);

    // rd: the old value, a `.w` form's word sign-extended; `sc` writes 0.
    f.gate(
        "rd_lo_rule",
        Expr::from(sel) - (all - w(kind::SC_W) - d(kind::SC_W)) * old,
    );
    f.gate(
        "rd_hi_rule",
        Expr::from(sel_hi)
            - (double - d(kind::SC_W)) * old_hi
            - (word - w(kind::SC_W)) * old_sign * ones,
    );
    f
}

/// The family's circuit over `2^trace_vars` rows, `docs/spec/memory-ops.md`
/// §6. Panics on every refusal of the assembly, and if the doubleword index's
/// high halfword, which a literal scales, lacks its direct bound.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    let f = spec();
    let live = f.live();
    let a = f.artifact(trace_vars);
    let dw_h = a
        .witness
        .iter()
        .position(|n| n == "dword_index_h16")
        .expect("the index's high halfword");
    if let Err(e) = check_copowers(&a, &[(PolyAddress::Witness(dw_h as u32), live)]) {
        panic!("atomics: {e}");
    }
    a
}

/// The family's channels, in output order.
pub fn channels() -> Vec<ChannelSpec> {
    spec().channels()
}
