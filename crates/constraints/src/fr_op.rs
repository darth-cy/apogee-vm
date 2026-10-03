//! The `FR_OP` family's circuit: one field operation a row over cells of the
//! field memory, invoked by `ecall::PRECOMPILE_FR_OP` and never decoded.
//!
//! `docs/spec/recursion.md` §3 is normative.
//!
//! ```text
//! frame     M[0..20]   cycle live base anchor_value, then 4 per word of [op, d, a, b]
//! M[20..23]            a_live a_read_ts a          the first operand, read at Δ0
//! M[23..26]            b_live b_read_ts b          the second, read at Δ1
//! M[26..30]            d_live d_read_ts d d_new    the destination, read and written at Δ2
//! W[0..12]             the frame's gap chunks and base bounds
//! W[12..18]            two gap chunks each for a, b and d
//! W[18..26]            one selector per op, `fr_op::OPS` order
//! W[26..29]            x prod z
//! W[29]                the RANGE16 channel's multiplicity
//! ```
//!
//! The cells are the frame's words, so a row names no address column of its
//! own: `a`'s cell is word 2's value, and so on. Each access carries a mask an
//! op selector sets, because an `IMM` reads nothing and an `EQ` writes nothing.
//!
//! **One product serves every op that multiplies.** `x` is `b` on `MUL` and
//! `MAC` and `d′` on `INV`, so `prod = a·x` is the one degree-2 product and each
//! op's equation stays degree 2 under its selector. `INV` is the is-zero
//! gadget: `a·d′ = 1 − z` with `z·a = 0` and `z·d′ = 0`, which leaves `d′ = a⁻¹`
//! where `a ≠ 0` and `d′ = 0` where `a = 0`.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::{address_space, fr_op as f};

use crate::delegation::{self as d, booleanity, linear, lit, neg, quadratic, Access, LIVE};
use crate::{CircuitArtifact, Coeff, GateDef, PolyAddress, VirtualKind};

/// The frame's words: `[op, d, a, b]`.
const WORDS: usize = f::FRAME_WORDS;

/// The frame's `M` columns, which the family's own follow.
const FRAME_M: u32 = (d::HEAD_COLUMNS + 4 * WORDS) as u32;
/// The frame's `W` columns, which the family's own follow.
const FRAME_W: u32 = d::frame_witness_range16(WORDS);

const fn m(i: u32) -> PolyAddress {
    PolyAddress::Memory(FRAME_M + i)
}
const fn w(i: u32) -> PolyAddress {
    PolyAddress::Witness(FRAME_W + i)
}

/// `M[20]`: whether this row reads `a`.
pub const A_LIVE: PolyAddress = m(0);
/// `M[21]`: when `a` was last written.
pub const A_READ_TS: PolyAddress = m(1);
/// `M[22]`: `a`'s value.
pub const A: PolyAddress = m(2);
/// `M[23]`: whether this row reads `b`.
pub const B_LIVE: PolyAddress = m(3);
/// `M[24]`: when `b` was last written.
pub const B_READ_TS: PolyAddress = m(4);
/// `M[25]`: `b`'s value.
pub const B: PolyAddress = m(5);
/// `M[26]`: whether this row writes `d`.
pub const D_LIVE: PolyAddress = m(6);
/// `M[27]`: when `d` was last written.
pub const D_READ_TS: PolyAddress = m(7);
/// `M[28]`: `d`'s value before the row.
pub const D: PolyAddress = m(8);
/// `M[29]`: `d`'s value after it.
pub const D_NEW: PolyAddress = m(9);
pub const MEMORY_COLUMNS: usize = FRAME_M as usize + 10;

/// `W[12 + 2q + c]`: chunk `c` of access `q`'s timestamp gap — `a`, `b`, `d`.
pub const fn gap_chunk(q: usize, c: usize) -> PolyAddress {
    w((d::GAP_CHUNKS * q + c) as u32)
}
/// `W[18 + i]`: the selector of `fr_op::OPS[i]`, op code `i + 1`.
pub const fn selector(i: usize) -> PolyAddress {
    w(6 + i as u32)
}
/// `W[26]`: the multiplicand, `b` or `d′`.
pub const X: PolyAddress = w(14);
/// `W[27]`: `a·x`.
pub const PROD: PolyAddress = w(15);
/// `W[28]`: `INV`'s zero flag.
pub const Z: PolyAddress = w(16);
/// `W[29]`: the `RANGE16` channel's multiplicity, last in the witness.
pub const MULTIPLICITY: PolyAddress = w(17);
pub const WITNESS_COLUMNS: usize = FRAME_W as usize + 18;

// A selector's index is its code less one, which the gates below read off.
const _: () = {
    let mut i = 0;
    while i < f::OPS.len() {
        assert!(f::OPS[i] == i as u32 + 1);
        i += 1;
    }
};

/// The selector of op `code`.
const fn sel(code: u32) -> PolyAddress {
    selector(code as usize - 1)
}

/// Frame word `j`'s value.
fn frame(j: usize) -> PolyAddress {
    d::word(j, d::WORD_READ_VALUE)
}

/// The three accesses, `a`, `b`, `d`.
fn accesses() -> [Access; 3] {
    let access = |q: usize, name: &str, mask, word, delta, read_ts, read, write| Access {
        name: name.to_string(),
        space: address_space::FIELD,
        mask,
        addr: frame(word),
        offset: 0,
        delta,
        read_ts,
        read,
        write,
        gap: [gap_chunk(q, 0), gap_chunk(q, 1)],
    };
    [
        access(0, "a", A_LIVE, f::A_WORD, f::DELTA_A, A_READ_TS, A, A),
        access(1, "b", B_LIVE, f::B_WORD, f::DELTA_B, B_READ_TS, B, B),
        access(2, "d", D_LIVE, f::D_WORD, f::DELTA_D, D_READ_TS, D, D_NEW),
    ]
}

/// The circuit at `2^trace_vars` rows.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    let (mut enforcing, mut lookups) = d::read_only_frame_range16(WORDS, f::FRAME_BYTES as u64);
    enforcing.extend(gates());
    let accesses = accesses();
    for a in &accesses {
        lookups.extend(a.gap_lookups());
    }
    let mut scaled = d::frame_scaled_range16(WORDS);
    scaled.extend(accesses.iter().map(Access::scaled));
    let artifact = crate::memory::assemble(
        trace_vars,
        [memory_names(), witness_names(), Vec::new()],
        vec![(VirtualKind::Range16, "range16".to_string())],
        d::leaves_with(
            address_space::DELEGATION_FR_OP,
            WORDS,
            accesses.iter().map(Access::leaves).collect(),
        ),
        enforcing,
        lookups,
        &channels(),
    );
    if let Err(e) = crate::lookup::check_copowers(&artifact, &scaled) {
        panic!("fr_op: {e}");
    }
    assert_eq!(artifact.memory.len(), MEMORY_COLUMNS, "fr_op: M width");
    assert_eq!(artifact.witness.len(), WITNESS_COLUMNS, "fr_op: W width");
    artifact
}

/// Everything the family adds beside its frame.
fn gates() -> Vec<(String, GateDef)> {
    let op = frame(f::OP_WORD);
    let imm = frame(f::B_WORD);
    let mut out: Vec<(String, GateDef)> = Vec::new();
    for code in f::OPS {
        out.push((format!("op{code}_boolean"), booleanity(sel(code))));
    }
    // One op a live row, and the op the guest wrote.
    let mut one = vec![(neg(1), LIVE)];
    let mut word = vec![(neg(1), op)];
    for code in f::OPS {
        one.push((lit(1), sel(code)));
        word.push((lit(code as u64), sel(code)));
    }
    out.push(("one_op_a_live_row".to_string(), linear(one)));
    out.push(("op_word".to_string(), linear(word)));
    // Each access is on exactly when its op reads or writes it.
    for (name, mask, codes) in [
        (
            "a",
            A_LIVE,
            &[f::MUL, f::ADD, f::SUB, f::MAC, f::INV, f::EQ, f::SHL][..],
        ),
        ("b", B_LIVE, &[f::MUL, f::ADD, f::SUB, f::MAC, f::EQ][..]),
        (
            "d",
            D_LIVE,
            &[f::MUL, f::ADD, f::SUB, f::MAC, f::INV, f::IMM, f::SHL][..],
        ),
    ] {
        out.push((format!("{name}_live_boolean"), booleanity(mask)));
        let mut terms = vec![(lit(1), mask)];
        terms.extend(codes.iter().map(|c| (neg(1), sel(*c))));
        out.push((format!("{name}_live_rule"), linear(terms)));
    }
    out.push((
        "x_rule".to_string(),
        quadratic(
            vec![(lit(1), X)],
            vec![
                (neg(1), sel(f::MUL), B),
                (neg(1), sel(f::MAC), B),
                (neg(1), sel(f::INV), D_NEW),
            ],
        ),
    ));
    out.push((
        "prod_rule".to_string(),
        quadratic(vec![(lit(1), PROD)], vec![(neg(1), A, X)]),
    ));
    let rule = |code: u32, terms: &[(Coeff, PolyAddress)]| {
        quadratic(
            vec![],
            terms.iter().map(|(c, x)| (*c, sel(code), *x)).collect(),
        )
    };
    let two_32 = Coeff::Literal(-d::pow2(32));
    for (name, code, terms) in [
        ("mul", f::MUL, vec![(lit(1), D_NEW), (neg(1), PROD)]),
        (
            "add",
            f::ADD,
            vec![(lit(1), D_NEW), (neg(1), A), (neg(1), B)],
        ),
        (
            "sub",
            f::SUB,
            vec![(lit(1), D_NEW), (neg(1), A), (lit(1), B)],
        ),
        (
            "mac",
            f::MAC,
            vec![(lit(1), D_NEW), (neg(1), D), (neg(1), PROD)],
        ),
        ("eq", f::EQ, vec![(lit(1), A), (neg(1), B)]),
        ("imm", f::IMM, vec![(lit(1), D_NEW), (neg(1), imm)]),
        (
            "shl",
            f::SHL,
            vec![(lit(1), D_NEW), (two_32, A), (neg(1), imm)],
        ),
    ] {
        out.push((format!("{name}_rule"), rule(code, &terms)));
    }
    // `INV`: `a·d′ = 1 − z`, `z` flagging `a = 0` and zeroing `d′` there, and
    // `z` is 0 on every other row.
    out.push((
        "inv_rule".to_string(),
        quadratic(
            vec![(neg(1), sel(f::INV))],
            vec![(lit(1), sel(f::INV), PROD), (lit(1), sel(f::INV), Z)],
        ),
    ));
    out.push(("z_boolean".to_string(), booleanity(Z)));
    out.push((
        "z_kills_a".to_string(),
        quadratic(vec![], vec![(lit(1), Z, A)]),
    ));
    out.push((
        "z_kills_d".to_string(),
        quadratic(vec![], vec![(lit(1), Z, D_NEW)]),
    ));
    out.push((
        "z_only_inv".to_string(),
        quadratic(vec![(lit(1), Z)], vec![(neg(1), Z, sel(f::INV))]),
    ));
    out
}

/// The `M` column names, in layout order.
fn memory_names() -> Vec<String> {
    let mut out = d::memory_names(WORDS);
    for name in ["a_live", "a_read_ts", "a", "b_live", "b_read_ts", "b"] {
        out.push(name.to_string());
    }
    for name in ["d_live", "d_read_ts", "d", "d_new"] {
        out.push(name.to_string());
    }
    out
}

/// The `W` column names, in layout order.
fn witness_names() -> Vec<String> {
    let mut out = d::frame_names_range16(WORDS);
    for q in ["a", "b", "d"] {
        for c in 0..d::GAP_CHUNKS {
            out.push(format!("gap_{q}_c{c}"));
        }
    }
    for code in f::OPS {
        out.push(format!("op{code}"));
    }
    for name in ["x", "prod", "z", "mult_range16"] {
        out.push(name.to_string());
    }
    out
}

/// One channel, `RANGE16`.
pub fn channels() -> Vec<crate::lookup::ChannelSpec> {
    vec![crate::lookup::ChannelSpec {
        channel: constants::lookup_channel::RANGE16,
        table: vec![PolyAddress::Virtual(VirtualKind::Range16)],
        multiplicity: MULTIPLICITY,
    }]
}
