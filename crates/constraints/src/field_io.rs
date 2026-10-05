//! The `FIELD_IO` family's circuit: one move a row between eight RAM words and
//! a field cell, invoked by `ecall::PRECOMPILE_FIELD_IO` and never decoded.
//!
//! `docs/spec/recursion.md` §5 specifies it.
//!
//! ```text
//! frame     M[0..16]   cycle live base anchor_value, then 4 per word of [op, cell, ptr]
//! M[16..40]            per data word k: read_ts, read, write    at ptr + 4k, Δ1
//! M[40..43]            the cell's read_ts, old, new              at Δ0
//! W[0..10]             the frame's gap chunks and base bounds
//! W[10..26]            two gap chunks per data word
//! W[26..28]            the cell's gap chunks
//! W[28..30]            import, export
//! W[30..38]            each exported word's high halfword
//! W[38]                the RANGE16 channel's multiplicity
//! ```
//!
//! **No address column and no address bound.** A data word's address is the
//! frame's `ptr` plus `4k`, read straight into its leaves, and the memory
//! argument alone makes it a word some window initializes — one none does has
//! no tuple to balance against. **`EXPORT` proves congruence, not canonicity**:
//! the words are below `2^32` and `Σ_k w_k·2^{32k}` is the cell modulo `p`; a
//! guest that needs the canonical limbs compares them with `p` in RAM itself.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::{address_space, field_io as f};

use crate::delegation::{self as d, booleanity, linear, lit, neg, quadratic, Access, LIVE};
use crate::{CircuitArtifact, Coeff, GateDef, PolyAddress, VirtualKind};

/// The frame's words: `[op, cell, ptr]`.
const WORDS: usize = f::FRAME_WORDS;
/// The data words.
const DATA: usize = f::DATA_WORDS;

const FRAME_M: u32 = (d::HEAD_COLUMNS + 4 * WORDS) as u32;
const FRAME_W: u32 = d::frame_witness_range16(WORDS);

const fn m(i: u32) -> PolyAddress {
    PolyAddress::Memory(FRAME_M + i)
}
const fn w(i: u32) -> PolyAddress {
    PolyAddress::Witness(FRAME_W + i)
}

/// `M[16 + 3k]`: when data word `k` was last written.
pub const fn data_read_ts(k: usize) -> PolyAddress {
    m(3 * k as u32)
}
/// `M[17 + 3k]`: data word `k`'s value before the row.
pub const fn data_read(k: usize) -> PolyAddress {
    m(3 * k as u32 + 1)
}
/// `M[18 + 3k]`: data word `k`'s value after it.
pub const fn data_write(k: usize) -> PolyAddress {
    m(3 * k as u32 + 2)
}
/// `M[40]`: when the cell was last written.
pub const CELL_READ_TS: PolyAddress = m(3 * DATA as u32);
/// `M[41]`: the cell's value before the row.
pub const CELL_OLD: PolyAddress = m(3 * DATA as u32 + 1);
/// `M[42]`: the cell's value after it.
pub const CELL_NEW: PolyAddress = m(3 * DATA as u32 + 2);
pub const MEMORY_COLUMNS: usize = FRAME_M as usize + 3 * DATA + 3;

/// `W[10 + 2k + c]`: chunk `c` of data word `k`'s gap; `k = 8` is the cell's.
pub const fn gap_chunk(k: usize, c: usize) -> PolyAddress {
    w((d::GAP_CHUNKS * k + c) as u32)
}
/// `W[28]`: `IMPORT`'s selector.
pub const IMPORT: PolyAddress = w(2 * (DATA as u32 + 1));
/// `W[29]`: `EXPORT`'s selector.
pub const EXPORT: PolyAddress = w(2 * (DATA as u32 + 1) + 1);
/// `W[30 + k]`: exported word `k`'s high halfword.
pub const fn word_hi(k: usize) -> PolyAddress {
    w(2 * (DATA as u32 + 1) + 2 + k as u32)
}
/// `W[38]`: the `RANGE16` channel's multiplicity, last in the witness.
pub const MULTIPLICITY: PolyAddress = w(2 * (DATA as u32 + 1) + 2 + DATA as u32);
pub const WITNESS_COLUMNS: usize = FRAME_W as usize + 2 * (DATA + 1) + 3 + DATA;

/// Frame word `j`'s value.
fn frame(j: usize) -> PolyAddress {
    d::word(j, d::WORD_READ_VALUE)
}

/// The eight data words, then the cell.
fn accesses() -> Vec<Access> {
    let mut out: Vec<Access> = (0..DATA)
        .map(|k| Access {
            name: format!("data{k}"),
            space: address_space::RAM,
            mask: LIVE,
            addr: frame(f::PTR_WORD),
            offset: 4 * k as u64,
            delta: f::DATA_DELTA,
            read_ts: data_read_ts(k),
            read: data_read(k),
            write: data_write(k),
            gap: [gap_chunk(k, 0), gap_chunk(k, 1)],
        })
        .collect();
    out.push(Access {
        name: "cell".to_string(),
        space: address_space::FIELD,
        mask: LIVE,
        addr: frame(f::CELL_WORD),
        offset: 0,
        delta: f::CELL_DELTA,
        read_ts: CELL_READ_TS,
        read: CELL_OLD,
        write: CELL_NEW,
        gap: [gap_chunk(DATA, 0), gap_chunk(DATA, 1)],
    });
    out
}

/// The circuit at `2^trace_vars` rows.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    let (mut enforcing, mut lookups) = d::read_only_frame_range16(WORDS, f::FRAME_BYTES as u64);
    enforcing.extend(gates());
    let accesses = accesses();
    for a in &accesses {
        lookups.extend(a.gap_lookups());
    }
    for k in 0..DATA {
        lookups.extend(d::bound32(
            &format!("word{k}"),
            data_write(k),
            word_hi(k),
            EXPORT,
        ));
    }
    let mut scaled = d::frame_scaled_range16(WORDS);
    scaled.extend(accesses.iter().map(Access::scaled));
    let artifact = crate::memory::assemble(
        trace_vars,
        [memory_names(), witness_names(), Vec::new()],
        vec![(VirtualKind::Range16, "range16".to_string())],
        d::leaves_with(
            address_space::DELEGATION_FIELD_IO,
            WORDS,
            accesses.iter().map(Access::leaves).collect(),
        ),
        enforcing,
        lookups,
        &channels(),
    );
    if let Err(e) = crate::lookup::check_copowers(&artifact, &scaled) {
        panic!("field_io: {e}");
    }
    assert_eq!(artifact.memory.len(), MEMORY_COLUMNS, "field_io: M width");
    assert_eq!(artifact.witness.len(), WITNESS_COLUMNS, "field_io: W width");
    artifact
}

/// Everything the family adds beside its frame.
fn gates() -> Vec<(String, GateDef)> {
    let mut out: Vec<(String, GateDef)> = vec![
        ("import_boolean".to_string(), booleanity(IMPORT)),
        ("export_boolean".to_string(), booleanity(EXPORT)),
        (
            "one_op_a_live_row".to_string(),
            linear(vec![(lit(1), IMPORT), (lit(1), EXPORT), (neg(1), LIVE)]),
        ),
        (
            "op_word".to_string(),
            linear(vec![
                (lit(f::IMPORT as u64), IMPORT),
                (lit(f::EXPORT as u64), EXPORT),
                (neg(1), frame(f::OP_WORD)),
            ]),
        ),
    ];
    // `−Σ_k 2^{32k}·x_k`, under `selector`.
    let words = |selector: PolyAddress, x: &dyn Fn(usize) -> PolyAddress| {
        (0..DATA)
            .map(|k| (Coeff::Literal(-d::pow2(32 * k as u32)), selector, x(k)))
            .collect::<Vec<_>>()
    };
    // `IMPORT`: the cell takes the words' value, and the words stay.
    let mut import = vec![(lit(1), IMPORT, CELL_NEW)];
    import.extend(words(IMPORT, &data_read));
    out.push(("import_rule".to_string(), quadratic(vec![], import)));
    for k in 0..DATA {
        out.push((
            format!("import_keeps_word{k}"),
            quadratic(
                vec![],
                vec![
                    (lit(1), IMPORT, data_write(k)),
                    (neg(1), IMPORT, data_read(k)),
                ],
            ),
        ));
    }
    // `EXPORT`: the cell stays, and the words take a value congruent to it.
    out.push((
        "export_keeps_cell".to_string(),
        quadratic(
            vec![],
            vec![(lit(1), EXPORT, CELL_NEW), (neg(1), EXPORT, CELL_OLD)],
        ),
    ));
    let mut export = words(EXPORT, &data_write);
    export.push((lit(1), EXPORT, CELL_OLD));
    out.push(("export_rule".to_string(), quadratic(vec![], export)));
    out
}

/// The `M` column names, in layout order.
fn memory_names() -> Vec<String> {
    let mut out = d::memory_names(WORDS);
    for k in 0..DATA {
        for field in ["read_ts", "read", "write"] {
            out.push(format!("data{k}_{field}"));
        }
    }
    for name in ["cell_read_ts", "cell_old", "cell_new"] {
        out.push(name.to_string());
    }
    out
}

/// The `W` column names, in layout order.
fn witness_names() -> Vec<String> {
    let mut out = d::frame_names_range16(WORDS);
    for k in 0..=DATA {
        let name = if k < DATA {
            format!("data{k}")
        } else {
            "cell".to_string()
        };
        for c in 0..d::GAP_CHUNKS {
            out.push(format!("gap_{name}_c{c}"));
        }
    }
    out.push("import".to_string());
    out.push("export".to_string());
    for k in 0..DATA {
        out.push(format!("word{k}_hi"));
    }
    out.push("mult_range16".to_string());
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
