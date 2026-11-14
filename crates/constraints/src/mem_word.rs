//! The `MEM_WORD` family's circuit: `ld`, `sd`, `lw`, `lwu` and `sw`.
//!
//! `docs/spec/memory-ops.md` §3 specifies it. RAM is 32-bit words, so a
//! doubleword is two of them: the frame's `load` query is the word at the
//! address, which a store writes, and its `ram` query the word above it, a
//! doubleword's high word.

use alloc::vec::Vec;

use constants::extra_mask::mem_word as kind;
use constants::family;

use crate::family::{k, sum, Expr, Family, Imm, T32};
use crate::lookup::{check_copowers, ChannelSpec};
use crate::memory::{LOAD, RAM, RD, RS1, RS2};
use crate::CircuitArtifact;

/// The kinds, in `constants::extra_mask::mem_word` order.
pub const KINDS: [&str; 5] = ["lw", "sw", "ld", "sd", "lwu"];

/// The address, its high word's carry, and the doubleword index: shared by
/// the three memory families. `rs1 + imm`, 64 bits with `imm` sign-extended,
/// splits as `2^32·wrap + 8·dw + 4·bit2 + low`, `low` the caller's offset
/// below a word, and its high word must vanish mod `2^32`: every address is
/// below `2^32` (`docs/spec/memory-ops.md` §2). `dw < 2^29` by a halfword pair
/// and its scaled high chunk. Returns `(dw, bit2)`.
pub fn address(f: &mut Family, low: Expr) -> (crate::PolyAddress, crate::PolyAddress) {
    let (imm, neg) = (f.imm.expect("an imm"), f.neg.expect("a signed imm"));
    let (v1, vh1, live) = (f.v(RS1), f.vh(RS1), f.live());
    let wrap = f.bit("wrap");
    let hwrap = f.bit("hi_wrap");
    let dw = f.col("dword_index");
    let bit2 = f.bit("bit2");
    f.gate(
        "addr_split",
        v1 + imm - wrap * T32 - dw * 8 - bit2 * 4 - low,
    );
    f.gate("addr_hi", vh1 + wrap + neg * (T32 - 1) - hwrap * T32);
    let dw_h = f.word("dword_index", dw.into());
    f.range16("dword_index_hi_scaled", dw_h * 8, live);
    (dw, bit2)
}

fn spec() -> Family {
    let mut f = Family::new(family::MEM_WORD, &KINDS, Imm::Signed);
    let b = |j: u32| f.kinds[j as usize];
    let (lw, sw, ld, sd, lwu) = (
        b(kind::LW),
        b(kind::SW),
        b(kind::LD),
        b(kind::SD),
        b(kind::LWU),
    );
    let (v2, vh2, sel, sel_hi) = (f.v(RS2), f.vh(RS2), f.sel(), f.sel_hi());
    let (v_load, v_ram, w_load, w_ram) = (f.v(LOAD), f.v(RAM), f.wv(LOAD), f.wv(RAM));

    let all = sum(&f.kinds.clone());
    f.mask_rule(RS1, all.clone());
    f.mask_rule(RS2, sum(&[sw, sd]));
    f.mask_rule(LOAD, all);
    f.mask_rule(RAM, sum(&[ld, sd]));
    f.mask_rule(RD, sum(&[lw, ld, lwu]));
    let (d1, d2, dd) = (f.rs1, f.rs2, f.rd);
    f.addr_rule(RS1, d1.into());
    f.addr_rule(RS2, d2.into());
    f.addr_rule(RD, dd.into());
    f.value_masked(RS1);
    f.value_masked(RS2);
    let (seq, next_pc) = (f.seq, f.next_pc());
    f.gate("next_pc_rule", next_pc - seq);

    let (dw, bit2) = address(&mut f, Expr::default());
    f.gate("dword_aligned", sum(&[ld, sd]) * bit2);
    let word = dw * 8 + bit2 * 4;
    f.addr_rule(LOAD, word.clone());
    f.addr_rule(RAM, word + k(4));
    // A load writes back each word it read; a store writes rs2's words.
    let stores = sum(&[sw, sd]);
    f.gate("load_value_rule", w_load - v_load - stores * (v2 - v_load));
    f.gate("ram_value_rule", w_ram - v_ram - sd * (vh2 - v_ram));
    // rd: the word, extended by its sign for lw and by 0 for lwu, or the
    // doubleword. A RAM word need not be a word — advice is bound to nothing —
    // so both of rd's words carry their own range.
    let (_, sign) = f.signed_word("rd_lo", sel.into());
    f.word("rd_hi", sel_hi.into());
    f.gate("rd_lo_rule", sel - sum(&[lw, ld, lwu]) * v_load);
    f.gate("rd_hi_rule", sel_hi - ld * v_ram - lw * sign * (T32 - 1));
    f
}

/// The family's circuit over `2^trace_vars` rows, `docs/spec/memory-ops.md`
/// §3. Panics on every refusal of the assembly, and if the doubleword index's
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
    if let Err(e) = check_copowers(&a, &[(crate::PolyAddress::Witness(dw_h as u32), live)]) {
        panic!("mem_word: {e}");
    }
    a
}

/// The family's channels, in output order.
pub fn channels() -> Vec<ChannelSpec> {
    spec().channels()
}
