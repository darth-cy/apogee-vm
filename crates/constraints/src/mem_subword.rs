//! The `MEM_SUBWORD` family's circuit: `lb`, `lh`, `lbu`, `lhu`, `sb`, `sh`.
//!
//! `docs/spec/memory-ops.md` §4 specifies it: the columns, the gates, the
//! lookups and the argument. This file is that section as data, on
//! `crate::family`'s builder beside the memory frame.
//!
//! Memory is word-addressed, so a sub-word access names the same word cell
//! `mem_word` names, and the byte position lives only in the splice
//! `word = high·(w·p) + sub·p + low`. The splice power `p` and its copower
//! come from two degree-2 gates over the address's low two bits, not from a
//! table (`docs/spec/memory-ops.md` §4.1). A load writes `rd`'s low word and
//! its sign or zero extension; a store reads only `rs2`'s low word.

use alloc::string::String;
use alloc::vec::Vec;

use constants::extra_mask::mem_subword as kind;
use constants::{family, generic_table};

use crate::family::{k, sum, Family, Imm, T32};
use crate::lookup::{check_copowers, ChannelSpec};
use crate::mem_word::address;
use crate::memory::{LOAD, RAM, RD, RS1, RS2};
use crate::{CircuitArtifact, GateDef, PolyAddress};

/// The kinds, in `constants::extra_mask::mem_subword` order.
pub const KINDS: [&str; 6] = ["lb", "lh", "lbu", "lhu", "sb", "sh"];

/// Bits to a byte. The one place the width of a sub-word access is written:
/// every literal of [`splice_gates`] is derived from it, so the reduced-width
/// check evaluates the family's own gates rather than a transcription of them.
pub const BYTE_BITS: u32 = 8;

/// The gates [`splice_gates`] returns: those whose literals depend on the byte
/// width, or that read a column one of them defines.
const SPLICE: [&str; 12] = [
    "p_rule",
    "pcopow_rule",
    "wph_rule",
    "splice_rule",
    "high_scaled_rule",
    "sub_scaled_rule",
    "low_scaled_rule",
    "src_sub_rule",
    "src_sub_scaled_rule",
    "sign_in_rule",
    "rd_value_rule",
    "store_rule",
];

/// The family at `byte_bits` bits to a byte; [`BYTE_BITS`] is the circuit.
fn spec(byte_bits: u32) -> Family {
    assert!(
        (1..=8).contains(&byte_bits),
        "mem_subword: a byte is 1 to 8 bits wide, not {byte_bits}"
    );
    let mut f = Family::new(family::MEM_SUBWORD, &KINDS, Imm::Signed);
    let b = |j: u32| f.kinds[j as usize];
    let (lb, lh, lbu, lhu, sb, sh) = (
        b(kind::LB),
        b(kind::LH),
        b(kind::LBU),
        b(kind::LHU),
        b(kind::SB),
        b(kind::SH),
    );
    let loads = sum(&[lb, lh, lbu, lhu]);
    let stores = sum(&[sb, sh]);
    let bytes = sum(&[lb, lbu, sb]);
    let (v2, sel, sel_hi, live) = (f.v(RS2), f.sel(), f.sel_hi(), f.live());
    let (m_ram, v_load, v_ram, w_load, w_ram) =
        (f.m(RAM), f.v(LOAD), f.v(RAM), f.wv(LOAD), f.wv(RAM));

    f.mask_rule(RS1, loads.clone() + stores.clone());
    f.mask_rule(RS2, stores.clone());
    f.mask_rule(LOAD, loads.clone());
    f.mask_rule(RAM, stores.clone());
    f.mask_rule(RD, loads.clone());
    let (d1, d2, dd) = (f.rs1, f.rs2, f.rd);
    f.addr_rule(RS1, d1.into());
    f.addr_rule(RS2, d2.into());
    f.addr_rule(RD, dd.into());
    f.value_masked(RS1);
    f.value_masked(RS2);
    f.gate("load_writes_back", w_load - v_load);
    let (seq, next_pc) = (f.seq, f.next_pc());
    f.gate("next_pc_rule", next_pc - seq);

    // addr = 8·dw + 4·bit2 + 2·bit1 + bit0: the word at 8·dw + 4·bit2, the byte
    // offset below it.
    let bit0 = f.bit("bit0");
    let bit1 = f.bit("bit1");
    let (dw, bit2) = address(&mut f, bit1 * 2 + bit0);
    let word_addr = dw * 8 + bit2 * 4;
    f.addr_rule(LOAD, word_addr.clone());
    f.addr_rule(RAM, word_addr);
    // A halfword access has bit 0 clear, which keeps w·p a divisor of 2^32.
    f.gate("half_aligned", sum(&[lh, lhu, sh]) * bit0);

    let (byte, half) = (1u64 << byte_bits, 1u64 << (2 * byte_bits));
    let (cube, whole) = (1u64 << (3 * byte_bits), 1u64 << (4 * byte_bits));
    let kk = cube - half - byte + 1;
    let p = f.col("p");
    let pcopow = f.col("pcopow");
    let wph = f.col("wph");
    let p_ram = f.col("p_ram");
    let word = f.col("word");
    let high = f.col("high");
    let high_scaled = f.col("high_scaled");
    let sub = f.col("sub");
    let sub_scaled = f.col("sub_scaled");
    let low = f.col("low");
    let low_scaled = f.col("low_scaled");
    let src_sub = f.col("src_sub");
    let src_sub_scaled = f.col("src_sub_scaled");
    let src_high = f.col("src_high");
    let sign_in = f.col("sign_in");
    let sign = f.col("sign");
    let se = f.col("se");

    f.gate("word_rule", word - loads.clone() * v_load - stores * v_ram);
    f.gate("p_ram_rule", p_ram - m_ram * p);
    f.gate("se_rule", se - sum(&[lb, lh]) * sign);
    // p = 2^(b·offset), the unique degree-2 form over the two offset bits;
    // m_pc stands for the constant so the all-zero row satisfies it.
    f.gate(
        "p_rule",
        p - live - bit0 * (byte - 1) - bit1 * (half - 1) - bit0 * bit1 * kk,
    );
    // p·pcopow = 2^(W−1) on a live row: the copower, halved to fit a word.
    f.gate("pcopow_rule", p * pcopow - live * (whole / 2));
    // wph = w·p/2, w = 2^2b − (2^2b − 2^b)·BYTE, halved for the same reason.
    f.gate(
        "wph_rule",
        wph - p * (half / 2) + bytes.clone() * p * ((half - byte) / 2),
    );
    f.gate("splice_rule", word - high_scaled - low - sub * p);
    f.gate("high_scaled_rule", high_scaled - high * wph * 2);
    f.gate(
        "sub_scaled_rule",
        sub_scaled - sub * (whole / half) - bytes.clone() * sub * (whole / byte - whole / half),
    );
    f.gate("low_scaled_rule", low_scaled - low * pcopow * 2);
    // rs2's low word = src_sub + w·src_high: the stored source truncated to the
    // access width.
    f.gate(
        "src_sub_rule",
        v2 - src_sub - src_high * half + bytes.clone() * src_high * (half - byte),
    );
    f.gate(
        "src_sub_scaled_rule",
        src_sub_scaled
            - src_sub * (whole / half)
            - bytes.clone() * src_sub * (whole / byte - whole / half),
    );
    // sign_in = sub·2^b for a byte, sub for a halfword: its bit 2b−1 is the
    // sub-word's sign at either width.
    f.gate(
        "sign_in_rule",
        sign_in - sub - bytes.clone() * sub * (byte - 1),
    );
    f.gate(
        "rd_value_rule",
        sel - se * (whole - half) - loads * sub - bytes * se * (half - byte),
    );
    f.gate(
        "store_rule",
        w_ram - m_ram * word - src_sub * p_ram + sub * p_ram,
    );
    // rd's high word: all ones on a sign-extended negative sub-word, else 0.
    f.gate("rd_hi_rule", sel_hi - se * (T32 - 1));

    for (name, value) in [
        ("high", high),
        ("high_scaled", high_scaled),
        ("sub_scaled", sub_scaled),
        ("low", low),
        ("low_scaled", low_scaled),
        ("src_sub_scaled", src_sub_scaled),
        ("src_high", src_high),
        ("rd", sel),
    ] {
        f.word(name, value.into());
    }
    // sub and src_sub are below the access width, at most a halfword, so one
    // halfword obligation each is their exact direct bound.
    f.range16("sub_range", sub.into(), live);
    f.range16("src_sub_range", src_sub.into(), live);
    // The sign lookup's tag bounds sign_in by the SIGN sub-table itself.
    f.generic(
        "sub_get_sign",
        k(generic_table::SIGN as u64),
        [Some(sign_in), Some(sign), None],
        live,
    );
    f
}

/// The splice, at `byte_bits` bits to a byte and `4·byte_bits` to a word: the
/// twelve gates whose literals depend on that width, or that read a column one
/// of them defines, over this family's own columns — the gates the circuit
/// takes at [`BYTE_BITS`], so a reduced-width check runs the circuit and not a
/// copy of it. Panics unless `1 <= byte_bits <= 8`.
pub fn splice_gates(byte_bits: u32) -> Vec<(String, GateDef)> {
    spec(byte_bits)
        .gates()
        .iter()
        .filter(|(name, _)| SPLICE.contains(&name.as_str()))
        .cloned()
        .collect()
}

/// The family's circuit over `2^trace_vars` rows, `docs/spec/memory-ops.md`
/// §4. Panics on every refusal of the assembly, and if a column a copower or a
/// literal scales lacks its direct range check under the same selector.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    let f = spec(BYTE_BITS);
    let live = f.live();
    let a = f.artifact(trace_vars);
    let col = |name: &str| {
        let i = a.witness.iter().position(|n| n == name).expect("a column");
        (PolyAddress::Witness(i as u32), live)
    };
    let scaled = ["dword_index_h16", "high", "sub", "low", "src_sub"].map(col);
    if let Err(e) = check_copowers(&a, &scaled) {
        panic!("mem_subword: {e}");
    }
    a
}

/// The family's channels, in output order.
pub fn channels() -> Vec<ChannelSpec> {
    spec(BYTE_BITS).channels()
}
