//! The `BITWISE` family's circuit: `and`, `or`, `xor` and their immediate
//! forms over 64-bit registers, eight byte lookups a row.
//!
//! `docs/spec/bitwise.md` specifies it. A row decomposes `rs1` and the second
//! operand `rs2 + imm` into eight bytes each and looks up each pair's AND,
//! which bounds both bytes; OR and XOR are linear forms over it:
//! `a | b = a + b − (a & b)` and `a ^ b = a + b − 2·(a & b)`, byte by byte,
//! no carry crossing a byte.

use alloc::format;
use alloc::vec::Vec;

use constants::extra_mask::bitwise as kind;
use constants::{family, generic_table};

use crate::family::{k, sum, Expr, Family, Imm, T32};
use crate::lookup::ChannelSpec;
use crate::memory::{RD, RS1, RS2};
use crate::{CircuitArtifact, PolyAddress};

/// The kinds, in `constants::extra_mask::bitwise` order.
pub const KINDS: [&str; 6] = ["xori", "ori", "andi", "xor", "or", "and"];

/// `Σ_j 2^(8j)·bytes[j]`.
fn packed(bytes: &[PolyAddress]) -> Expr {
    bytes
        .iter()
        .enumerate()
        .fold(Expr::default(), |acc, (j, x)| acc + *x * (1u64 << (8 * j)))
}

fn spec() -> Family {
    let mut f = Family::new(family::BITWISE, &KINDS, Imm::Signed);
    let b = |j: u32| f.kinds[j as usize];
    let (xori, ori, andi) = (b(kind::XORI), b(kind::ORI), b(kind::ANDI));
    let (xor, or, and) = (b(kind::XOR), b(kind::OR), b(kind::AND));
    let (imm, neg) = (f.imm.expect("an imm"), f.neg.expect("a signed imm"));
    let (v1, v2, vh1, vh2) = (f.v(RS1), f.v(RS2), f.vh(RS1), f.vh(RS2));
    let (sel, sel_hi, live) = (f.sel(), f.sel_hi(), f.live());

    let all = sum(&f.kinds.clone());
    f.mask_rule(RS1, all.clone());
    f.mask_rule(RS2, sum(&[xor, or, and]));
    f.mask_rule(RD, all);
    let (d1, d2, dd) = (f.rs1, f.rs2, f.rd);
    f.addr_rule(RS1, d1.into());
    f.addr_rule(RS2, d2.into());
    f.addr_rule(RD, dd.into());
    f.value_masked(RS1);
    f.value_masked(RS2);
    let (seq, next_pc) = (f.seq, f.next_pc());
    f.gate("next_pc_rule", next_pc - seq);

    let a: Vec<PolyAddress> = (0..8).map(|j| f.col(&format!("byte_a{j}"))).collect();
    let c: Vec<PolyAddress> = (0..8).map(|j| f.col(&format!("byte_b{j}"))).collect();
    let n: Vec<PolyAddress> = (0..8).map(|j| f.col(&format!("byte_and{j}"))).collect();
    for j in 0..8 {
        f.generic(
            &format!("and_byte_{j}"),
            k(generic_table::AND as u64),
            [Some(a[j]), Some(c[j]), Some(n[j])],
            live,
        );
    }
    // The second operand is rs2 + imm: an immediate form reads no rs2, and a
    // register form's imm is 0, so one addend is always 0 and there is no
    // carry; its high word is rs2's or the immediate's sign extension.
    f.gate("rs1_lo_bytes", v1 - packed(&a[..4]));
    f.gate("rs1_hi_bytes", vh1 - packed(&a[4..]));
    f.gate("src2_lo_bytes", v2 + imm - packed(&c[..4]));
    f.gate("src2_hi_bytes", vh2 + neg * (T32 - 1) - packed(&c[4..]));
    // rd = t1·(a + b) + t2·(a & b), word by word: AND at (0, 1), OR at
    // (1, −1), XOR at (1, −2).
    let t1 = sum(&[or, ori, xor, xori]);
    let t2 = sum(&[and, andi]) - or - ori - (Expr::from(xor) + xori) * 2;
    f.gate(
        "out_lo",
        Expr::from(sel) - t1.clone() * (v1 + v2 + imm) - t2.clone() * packed(&n[..4]),
    );
    f.gate(
        "out_hi",
        Expr::from(sel_hi) - t1.clone() * (vh1 + vh2) - t1 * neg * (T32 - 1) - t2 * packed(&n[4..]),
    );
    f
}

/// The family's circuit over `2^trace_vars` rows, `docs/spec/bitwise.md`.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    spec().artifact(trace_vars)
}

/// The family's channels, in output order.
pub fn channels() -> Vec<ChannelSpec> {
    spec().channels()
}
