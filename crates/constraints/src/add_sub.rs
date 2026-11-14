//! The `ADD_SUB_LUI_AUIPC` family's circuit: `add`, `sub`, `addi`, `lui`,
//! `auipc`, their 32-bit forms `addw`, `subw`, `addiw`, and the system row
//! kind with its one provable ecall, `exit`.
//!
//! `docs/spec/add-sub.md` specifies it: the columns, the gates, the lookups
//! and the argument. This file is that page as data, on `crate::family`'s
//! builder beside the memory frame.

use alloc::vec::Vec;
use constants::extra_mask::add_sub_lui_auipc as kind;
use constants::extra_mask::system_code;

use constants::{ecall, family, memory as mem};

use crate::family::{sum, Expr, Family, Imm, T32};
use crate::lookup::ChannelSpec;
use crate::memory::{RD, RS1, RS2};
use crate::CircuitArtifact;

/// The kinds, in `constants::extra_mask::add_sub_lui_auipc` order.
pub const KINDS: [&str; 9] = [
    "system", "addi", "auipc", "add", "sub", "lui", "addiw", "addw", "subw",
];

/// `ecall_code` is `is_ecall·imm`, which says "the code is `ECALL`" only
/// because that code is 0.
const _: () = assert!(system_code::ECALL == 0);

/// `a7`'s register, which an ecall row reads as its `rs1`.
const A7: u64 = 17;
/// `a0`'s register, which an ecall row reads as its `rs2` and writes as its
/// `rd`.
const A0: u64 = 10;

fn spec() -> Family {
    let mut f = Family::new(family::ADD_SUB_LUI_AUIPC, &KINDS, Imm::Signed);
    let b = |j: u32| f.kinds[j as usize];
    let (system, addi, auipc, add, sub, lui) = (
        b(kind::SYSTEM),
        b(kind::ADDI),
        b(kind::AUIPC),
        b(kind::ADD),
        b(kind::SUB),
        b(kind::LUI),
    );
    let (addiw, addw, subw) = (b(kind::ADDIW), b(kind::ADDW), b(kind::SUBW));
    let (imm, neg) = (f.imm.expect("an imm"), f.neg.expect("a signed imm"));
    let (v1, v2, vh1, vh2) = (f.v(RS1), f.v(RS2), f.vh(RS1), f.vh(RS2));
    let (sel, sel_hi, pc) = (f.sel(), f.sel_hi(), f.pc());
    let ones = T32 - 1;

    let is_ecall = f.bit("is_ecall");
    let is_fence = f.bit("is_fence");
    f.gate("system_split", is_ecall + is_fence - system);
    f.gate("ecall_code", is_ecall * imm);
    f.gate(
        "fence_code",
        is_fence * imm - is_fence * system_code::FENCE as u64,
    );
    // An ecall row is an exit, and `a7` is its number, 64 bits of it.
    f.gate(
        "ecall_is_exit",
        is_ecall * v1 - is_ecall * ecall::EXIT as u64,
    );
    f.gate("ecall_is_exit_hi", is_ecall * vh1);

    let reads_rs1 = sum(&[add, sub, addi, addw, subw, addiw, is_ecall]);
    let reads_rs2 = sum(&[add, sub, addw, subw, is_ecall]);
    let writes = sum(&[add, sub, addi, auipc, lui, addiw, addw, subw, is_ecall]);
    f.mask_rule(RS1, reads_rs1);
    f.mask_rule(RS2, reads_rs2);
    f.mask_rule(RD, writes);
    let (d1, d2, dd) = (f.rs1, f.rs2, f.rd);
    f.addr_rule(RS1, d1 + is_ecall * A7);
    f.addr_rule(RS2, d2 + is_ecall * A0);
    f.addr_rule(RD, dd + is_ecall * A0);
    f.value_masked(RS1);
    f.value_masked(RS2);

    let c0 = f.bit("c0");
    let c1 = f.bit("c1");
    // The low word: one addition, its carry c0, for every kind that adds; an
    // absent operand reads 0 and an R-type row's imm is the table's 0, so each
    // kind sees its own two addends, auipc's pc among them.
    let adds = sum(&[add, addi, auipc, addw, addiw]);
    f.gate(
        "add_lo",
        adds * (v1 + v2 + imm - sel - c0 * T32) + auipc * pc,
    );
    f.gate("sub_lo", sum(&[sub, subw]) * (v1 - v2 - sel + c0 * T32));
    f.gate("lui_lo", lui * (imm - sel));
    // The high word of a 64-bit kind: the operands' high words, the carry in,
    // and an immediate's high word `(2^32 − 1)·neg`.
    let adds64 = sum(&[add, addi, auipc]);
    f.gate(
        "add_hi",
        adds64.clone() * (vh1 + vh2 + c0 - sel_hi - c1 * T32) + adds64 * neg * ones,
    );
    f.gate("sub_hi", sub * (vh1 - vh2 - c0 - sel_hi + c1 * T32));
    f.gate("lui_hi", lui * neg * ones - lui * sel_hi);
    // A W kind writes its 32-bit result sign-extended.
    let (_, w_sign) = f.signed_word("rd_lo", sel.into());
    f.gate(
        "w_extend",
        sum(&[addw, addiw, subw]) * (Expr::from(sel_hi) - w_sign * ones),
    );
    f.word("rd_hi", sel_hi.into());
    // The exit row's `a0` write is its read.
    let (v_rd, vh_rd) = (f.v(RD), f.vh(RD));
    f.gate("exit_status", is_ecall * v_rd - is_ecall * sel);
    f.gate("exit_status_hi", is_ecall * vh_rd - is_ecall * sel_hi);

    // next_pc + 2^32·pc_wrap = decoded_next_pc, or HALT_PC on the exit row.
    let pc_wrap = f.bit("pc_wrap");
    let (next_pc, seq) = (f.next_pc(), f.seq);
    f.gate(
        "next_pc_rule",
        next_pc + pc_wrap * T32 - seq + is_ecall * seq - is_ecall * mem::HALT_PC as u64,
    );
    f.word("next_pc", next_pc.into());
    f
}

/// The family's circuit over `2^trace_vars` rows, `docs/spec/add-sub.md`.
/// `trace_vars` is at least 19, the timestamp channel's width, which the
/// registry refuses below. Panics on every refusal of the assembly.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    spec().artifact(trace_vars)
}

/// The family's channels, in output order: the timestamp gaps over
/// `V[range19]`, the halfwords over `V[range16]`, the sign over the generic
/// table and the decoder over the family's decoded table.
pub fn channels() -> Vec<ChannelSpec> {
    spec().channels()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ebreak`'s code is neither the ecall code nor the fence code, which is
    /// what makes `system_split` with `ecall_code` and `fence_code` refuse every
    /// `ebreak` row.
    #[test]
    fn no_system_code_is_both_or_neither_but_ebreak() {
        assert_ne!(system_code::EBREAK, system_code::ECALL);
        assert_ne!(system_code::EBREAK, system_code::FENCE);
        assert_ne!(system_code::ECALL, system_code::FENCE);
    }
}
