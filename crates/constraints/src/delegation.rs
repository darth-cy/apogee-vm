//! The delegation frame, shared by every delegation circuit.
//!
//! Every delegation family proves the same thing about its frame: the `2^n`
//! rows are invocations, one row is one call, the frame is `words`
//! fixed-offset RAM words at `base + 4j`, and the anchor is two leaves in the
//! family's own address space that pair the invocation with exactly one
//! request (`constants::delegation`). This module is that paragraph as data —
//! the memory columns, the leaves and the bounds — so a family's own file,
//! `keccak.rs` or `sha256.rs`, holds only the function it delegates.
//!
//! # The layout every delegation family shares
//!
//! ```text
//! M[0]              cycle          the requesting cycle
//! M[1]              live           the row's one mask
//! M[2]              base           the frame base pointer
//! M[3]              anchor_value   the teardown's value, free on both sides
//! M[4 + 4j + f]     frame word j:  addr, read_ts, read_value, write_value
//!
//! W, over RANGE16 (each family at 2^16 and above):
//! W[2j + c]         frame word j's two timestamp-gap chunks
//! W[2·words + ..]   base_low, base_low_hi, base_room, base_room_hi
//! ```

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::{challenge_slot, guest_memory, lookup_channel, memory as mem};
use field::Fr;

use crate::{Coeff, GateDef, LookupExpr, PolyAddress};

// An invocation's frame writes must land on a `(space, Δ)` pair no frame query
// of the table holds, or the frame builder would file them into the requesting
// row. A `const` assertion rather than a test, because a violation is a broken
// ABI, not a failing case.
const _: () = {
    let mut q = 0;
    while q < crate::memory::FRAME_QUERIES {
        assert!(
            !(crate::memory::FRAME_SPACE[q] == constants::address_space::RAM
                && crate::memory::FRAME_DELTA[q] == constants::delegation::FRAME_DELTA),
            "a frame query already holds (RAM, FRAME_DELTA): an invocation's frame events \
             would be filed into the requesting row"
        );
        q += 1;
    }
};

// ---------------------------------------------------------------------------
// The committed columns
// ---------------------------------------------------------------------------

/// `M[0]`: the cycle whose ecall requested this invocation.
pub const CYCLE: PolyAddress = PolyAddress::Memory(0);
/// `M[1]`: the row's one mask. The frame and the anchor are one invocation:
/// live together or not at all.
pub const LIVE: PolyAddress = PolyAddress::Memory(1);
/// `M[2]`: the frame base pointer the request handed over in `a0`.
pub const BASE: PolyAddress = PolyAddress::Memory(2);
/// `M[3]`: the teardown read's value, free on both sides of the anchor.
pub const ANCHOR_VALUE: PolyAddress = PolyAddress::Memory(3);

/// The four `M` columns every delegation frame carries before its words.
pub const HEAD_COLUMNS: usize = 4;

/// A frame word's field: its address, `base + 4j`.
pub const WORD_ADDR: u32 = 0;
/// A frame word's field: the timestamp of the write its read consumed.
pub const WORD_READ_TS: u32 = 1;
/// A frame word's field: the value it read.
pub const WORD_READ_VALUE: u32 = 2;
/// A frame word's field: the value it wrote, at `4·cycle + FRAME_DELTA`.
pub const WORD_WRITE_VALUE: u32 = 3;

/// `M[4 + 4j + field]`: one field of frame word `j`.
pub fn word(j: usize, field: u32) -> PolyAddress {
    PolyAddress::Memory(HEAD_COLUMNS as u32 + 4 * j as u32 + field)
}

/// The `M` column names, in layout order.
pub fn memory_names(words: usize) -> Vec<String> {
    let mut out = vec![
        "cycle".to_string(),
        "live".to_string(),
        "base".to_string(),
        "anchor_value".to_string(),
    ];
    for j in 0..words {
        for field in ["addr", "read_ts", "read_value", "write_value"] {
            out.push(format!("w{j}_{field}"));
        }
    }
    out
}

/// Bits in `(base − RAM_ORIGIN) / 4`, which is below `2^31 / 4`.
pub const BASE_LOW_BITS: usize = 29;
/// Bits in `2^31 − frame bytes − base`.
pub const BASE_ROOM_BITS: usize = 31;

// ---------------------------------------------------------------------------
// Gate constructors
// ---------------------------------------------------------------------------

pub(crate) fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

pub(crate) fn neg(v: u64) -> Coeff {
    Coeff::Literal(-Fr::from_u64(v))
}

fn slot(s: u32) -> Coeff {
    Coeff::Challenge(s)
}

/// `x − x·x`, which holds exactly at `x ∈ {0, 1}`.
///
/// Byte-identical to `crate::memory`'s, which `check_memory` compares
/// structurally when it looks for a leaf mask's booleanity gate.
pub(crate) fn booleanity(x: PolyAddress) -> GateDef {
    GateDef::Quadratic {
        constant: lit(0),
        linear: vec![(lit(1), x)],
        products: vec![(neg(1), x, x)],
    }
}

pub(crate) fn quadratic(
    linear: Vec<(Coeff, PolyAddress)>,
    products: Vec<(Coeff, PolyAddress, PolyAddress)>,
) -> GateDef {
    GateDef::Quadratic {
        constant: lit(0),
        linear,
        products,
    }
}

pub(crate) fn linear(terms: Vec<(Coeff, PolyAddress)>) -> GateDef {
    GateDef::Linear {
        terms,
        constant: lit(0),
    }
}

/// `2^n` as a field element, for an `n` a `u64` literal cannot hold.
pub(crate) fn pow2(n: u32) -> Fr {
    let mut out = Fr::ONE;
    let two = Fr::from_u64(2);
    for _ in 0..n {
        out *= two;
    }
    out
}

/// A leaf's timestamp: the literal 0, a column, or this row's
/// `4·cycle + delta`.
pub(crate) enum Timestamp {
    Zero,
    Column(PolyAddress),
    Write(u64),
}

/// One memory leaf: `live·T(space, addr, ts, value) + 1 − live`, written flat
/// as `docs/spec/memory.md` §2.2 writes one.
pub(crate) fn leaf(
    space: u8,
    addr: PolyAddress,
    ts: Timestamp,
    value: Option<PolyAddress>,
) -> GateDef {
    let mut lin = vec![
        (slot(challenge_slot::MEM_GAMMA), LIVE),
        (neg(1), LIVE),
        (lit(space as u64), LIVE),
    ];
    let mut products = vec![(slot(challenge_slot::MEM_ALPHA_ADDR), addr, LIVE)];
    match ts {
        Timestamp::Zero => {}
        Timestamp::Column(column) => {
            products.push((slot(challenge_slot::MEM_ALPHA_TS), column, LIVE));
        }
        Timestamp::Write(delta) => {
            // `4·cycle + delta`: a coefficient is one literal or one challenge,
            // so `α_ts·4·cycle` is the term repeated four times and
            // `α_ts·delta·live` `delta` times (`docs/spec/memory.md` §1).
            for _ in 0..mem::TS_STEP {
                products.push((slot(challenge_slot::MEM_ALPHA_TS), CYCLE, LIVE));
            }
            for _ in 0..delta {
                lin.push((slot(challenge_slot::MEM_ALPHA_TS), LIVE));
            }
        }
    }
    if let Some(value) = value {
        products.push((slot(challenge_slot::MEM_ALPHA_VAL), value, LIVE));
    }
    GateDef::Quadratic {
        constant: lit(1),
        linear: lin,
        products,
    }
}

/// A leaf that is the product's identity.
pub(crate) fn pad_leaf() -> GateDef {
    GateDef::Linear {
        terms: Vec::new(),
        constant: lit(1),
    }
}

// ---------------------------------------------------------------------------
// The memory subtree
// ---------------------------------------------------------------------------

/// Leaves a side: the frame's `words` plus the anchor's one, padded to a power
/// of two with leaves that are literally 1.
pub fn leaves_a_side(words: usize) -> usize {
    (words + 1).next_power_of_two()
}

/// The read side and the write side of the memory subtree, each padded.
///
/// Read: one leaf per frame word, consuming the write it names, then the
/// anchor's **teardown** — `T(space, base, 4·cycle + ANCHOR_DELTA,
/// anchor_value)`, the tuple the requesting row's mirror query wrote back.
/// Write: one leaf per frame word at `4·cycle + FRAME_DELTA`, then the
/// anchor's **answer** — `T(space, base, 0, 0)`, stamped 0, which is the stamp
/// no ordinary cycle can produce and which exactly one request may read.
///
/// **UNFINISHED: the request side** (`constants::delegation::ANCHOR_DELTA`).
/// No requesting row reads the answer or writes the teardown tuple yet, so
/// both anchor leaves are unmatched in the memory argument.
pub(crate) fn leaves(space: u8, words: usize) -> [Vec<(String, GateDef)>; 2] {
    let side = leaves_a_side(words);
    let mut reads: Vec<(String, GateDef)> = Vec::with_capacity(side);
    let mut writes: Vec<(String, GateDef)> = Vec::with_capacity(side);
    for j in 0..words {
        reads.push((
            format!("read_w{j}"),
            leaf(
                constants::address_space::RAM,
                word(j, WORD_ADDR),
                Timestamp::Column(word(j, WORD_READ_TS)),
                Some(word(j, WORD_READ_VALUE)),
            ),
        ));
        writes.push((
            format!("write_w{j}"),
            leaf(
                constants::address_space::RAM,
                word(j, WORD_ADDR),
                Timestamp::Write(constants::delegation::FRAME_DELTA),
                Some(word(j, WORD_WRITE_VALUE)),
            ),
        ));
    }
    reads.push((
        "read_anchor".to_string(),
        leaf(
            space,
            BASE,
            Timestamp::Write(constants::delegation::ANCHOR_DELTA),
            Some(ANCHOR_VALUE),
        ),
    ));
    writes.push((
        "write_anchor".to_string(),
        leaf(space, BASE, Timestamp::Zero, None),
    ));
    for i in 0..side - words - 1 {
        reads.push((format!("read_pad{i}"), pad_leaf()));
        writes.push((format!("write_pad{i}"), pad_leaf()));
    }
    [reads, writes]
}

// ---------------------------------------------------------------------------
// Range checks through the RANGE16 channel
// ---------------------------------------------------------------------------
//
// Both delegation families sit at `2^16` or above and bound through
// `RANGE16`, and the helpers below are what they share.

/// Bits a `RANGE16` chunk holds.
pub(crate) const CHUNK_BITS: u32 = 16;

/// One `RANGE16` obligation.
pub(crate) fn range16(name: String, selector: PolyAddress, tuple: GateDef) -> LookupExpr {
    LookupExpr {
        name,
        channel: lookup_channel::RANGE16,
        selector,
        tuple: vec![tuple],
    }
}

/// A 32-bit bound, `docs/spec/memory.md` §7's shape: the high halfword direct
/// and the derived low half, **one committed column and two obligations**.
///
/// `hi <= 2^16 - 1` and `x - 2^16*hi <= 2^16 - 1` give
/// `x = lo + 2^16*hi <= 2^32 - 1`, and the low expression is *defined* as the
/// remainder, so no wrap is possible.
pub(crate) fn bound32(
    name: &str,
    x: PolyAddress,
    hi: PolyAddress,
    selector: PolyAddress,
) -> Vec<LookupExpr> {
    vec![
        range16(
            format!("{name}_hi_range"),
            selector,
            linear(vec![(lit(1), hi)]),
        ),
        range16(
            format!("{name}_lo_range"),
            selector,
            linear(vec![(lit(1), x), (Coeff::Literal(-pow2(CHUNK_BITS)), hi)]),
        ),
    ]
}

/// A bound of `[0, 2^bits)` for a `bits` that is **not** a multiple of sixteen,
/// over `RANGE16`.
///
/// Write `bits = 16q + r` with `0 < r < 16`. Commit `q` chunks with weights
/// `2^16 .. 2^{16q}`; the low remainder is derived. Obligations:
///
/// ```text
/// chunk_c < 2^16                    direct, one per committed chunk
/// 2^(16 - r) * chunk_top < 2^16     scaled, so chunk_top < 2^r
/// x - sum 2^{16(c+1)} chunk_c < 2^16
/// ```
///
/// The maximum is `(2^16 - 1)(1 + 2^16 + … + 2^{16(q-1)}) + 2^{16q}(2^r - 1)`,
/// which is `2^bits - 1` exactly.
///
/// **The scaled obligation alone bounds nothing.** `2^{16-r}` is a unit in
/// `Fr`, so an unbounded `x` sweeps a coset of which almost no member is a
/// small integer, and the range check sees nothing wrong. It is the top
/// chunk's own direct obligation that establishes the premise, which is why
/// `lookup::check_copowers` requires the pair under the **same** selector, and
/// why every caller here passes one selector to both.
pub(crate) fn bound_chunked(
    name: &str,
    x: Vec<(Coeff, PolyAddress)>,
    chunks: &[PolyAddress],
    bits: u32,
    selector: PolyAddress,
    constant: Coeff,
) -> Vec<LookupExpr> {
    let q = chunks.len() as u32;
    assert!(
        bits > CHUNK_BITS * q && bits < CHUNK_BITS * (q + 1),
        "delegation: {name} needs {q} chunks for {bits} bits"
    );
    let r = bits - CHUNK_BITS * q;
    let mut out: Vec<LookupExpr> = Vec::new();
    for (c, chunk) in chunks.iter().enumerate() {
        out.push(range16(
            format!("{name}_c{c}_range"),
            selector,
            linear(vec![(lit(1), *chunk)]),
        ));
    }
    out.push(range16(
        format!("{name}_top_scaled"),
        selector,
        linear(vec![(
            lit(1u64 << (CHUNK_BITS - r)),
            chunks[chunks.len() - 1],
        )]),
    ));
    let mut low = x;
    for (c, chunk) in chunks.iter().enumerate() {
        low.push((Coeff::Literal(-pow2(CHUNK_BITS * (c as u32 + 1))), *chunk));
    }
    out.push(range16(
        format!("{name}_lo_range"),
        selector,
        GateDef::Linear {
            terms: low,
            constant,
        },
    ));
    out
}

/// Chunks a 38-bit timestamp gap takes over `RANGE16`: two committed, the low
/// one derived.
///
/// `TIMESTAMP` would be the natural channel and it does not fit a delegation
/// family — its table needs 19 variables, and those families sit at
/// `2^16` or `2^18`, where 19 variables need `2^20`, an execution family's
/// floor.
pub const GAP_CHUNKS: usize = 2;

/// The frame's own gates: `live`'s booleanity, the `words` address rules and
/// the two frame-pointer bounds. The timestamp gaps are obligations, not gates
/// ([`gap_lookups_range16`]), and each base decomposition is one committed
/// value plus one chunk.
///
/// The caller supplies the witness addresses, because their position in the
/// witness subtree is the family's business: `base_low` is the aligned
/// quotient `(base - RAM_ORIGIN) / 4` and `base_room` is
/// `2^31 - frame bytes - base`.
///
/// A gate that must be vacuous on the all-zero padding row carries `live` on
/// every term: on a padding row `addr` and `base` are 0 and `4j` is not.
pub(crate) fn frame_gates_range16(
    words: usize,
    frame_bytes: u64,
    base_low: PolyAddress,
    base_room: PolyAddress,
) -> Vec<(String, GateDef)> {
    let mut out: Vec<(String, GateDef)> = vec![("live_boolean".to_string(), booleanity(LIVE))];
    for j in 0..words {
        out.push((
            format!("addr_w{j}"),
            quadratic(
                vec![(neg(4 * j as u64), LIVE)],
                vec![(lit(1), LIVE, word(j, WORD_ADDR)), (neg(1), LIVE, BASE)],
            ),
        ));
    }
    out.push((
        "base_aligned".to_string(),
        quadratic(
            vec![(neg(guest_memory::RAM_ORIGIN as u64), LIVE)],
            vec![(lit(1), LIVE, BASE), (neg(4), LIVE, base_low)],
        ),
    ));
    let top = (1u64 << 31) - frame_bytes;
    out.push((
        "base_in_window".to_string(),
        quadratic(
            vec![(lit(top), LIVE)],
            vec![(neg(1), LIVE, BASE), (neg(1), LIVE, base_room)],
        ),
    ));
    out
}

/// The frame's timestamp-gap obligations, `[0, 2^38)` apiece over `RANGE16`.
///
/// The expression is `4*cycle + FRAME_DELTA - 1 - read_ts`, and the selector is
/// `live`: on a padding row it is `-1`, which is in no table, and the selector
/// is what exempts it. There is **no** `gap_w{j}` gate — the obligations are
/// the bound and the decomposition at once, exactly as `memory::gap_lookups`
/// has it for an execution family.
pub(crate) fn gap_lookups_range16(
    words: usize,
    chunk: &dyn Fn(usize, usize) -> PolyAddress,
) -> Vec<LookupExpr> {
    let mut out: Vec<LookupExpr> = Vec::new();
    for j in 0..words {
        let chunks: Vec<PolyAddress> = (0..GAP_CHUNKS).map(|c| chunk(j, c)).collect();
        out.extend(bound_chunked(
            &format!("gap{j}"),
            vec![(lit(mem::TS_STEP), CYCLE), (neg(1), word(j, WORD_READ_TS))],
            &chunks,
            mem::TS_BITS,
            LIVE,
            Coeff::Literal(Fr::from_u64(constants::delegation::FRAME_DELTA) - Fr::from_u64(1)),
        ));
    }
    out
}
