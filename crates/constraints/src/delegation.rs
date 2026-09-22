//! The delegation frame, shared by S23's two circuits.
//!
//! Every delegation family proves the same thing about its frame, and
//! `docs/spec/delegation.md` §4 and §5 say it once: the `2^n` rows are
//! invocations, one row is one call, the frame is `words` fixed-offset RAM
//! words at `base + 4j`, and the anchor is two leaves in the family's own
//! address space that pair the invocation with exactly one request. This
//! module is that paragraph as data — the memory columns, the leaves, the
//! bounds and the layered-artifact builder — so a family's own file holds only
//! the function it delegates.
//!
//! **`keccak` keeps its own copy.** S21's circuit is frozen, its artifact is
//! 100 MB and its fixture is a digest; rewriting it to call this module would
//! put a frozen artifact's bytes at risk for tidiness, which is a trade the
//! master's "build conservatively" refuses. What is here was written from it,
//! and `crates/checker/tests/delegation_frame.rs` holds the two spellings of
//! every shared gate equal so they cannot drift.
//!
//! # The committed layout every delegation family shares
//!
//! ```text
//! M[0]              cycle          the requesting cycle
//! M[1]              live           the row's one mask
//! M[2]              base           the frame base pointer
//! M[3]              anchor_value   the teardown's value, free on both sides
//! M[4 + 4j + f]     frame word j:  addr, read_ts, read_value, write_value
//! W[38j + i]        frame word j's 38 timestamp-gap bits
//! W[38·words + ..]  base_low (29 bits), then base_room (31 bits)
//! W[frame_witness(words) + ..]   the family's own
//! ```

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::{challenge_slot, guest_memory, memory as mem};
use field::Fr;

use crate::{
    CachedEntry, Coeff, EnforcingEntry, GateDef, LayerSpec, PolyAddress, ProducingEntry, Relation,
    ScratchSlot,
};

// The invocation's teardown read and the requesting row's mirror write are the
// same tuple, so their slots must agree; and an invocation's frame writes must
// land on a `(space, Δ)` pair no frame query of the table holds, or the frame
// builder would file them into the requesting row. Both are `const` assertions
// rather than tests because a violation is a broken ABI, not a failing case.
// `crates/constraints/src/keccak.rs` carries the same two.
const _: () =
    assert!(constants::delegation::ANCHOR_DELTA == crate::memory::FRAME_DELTA[crate::memory::DELEG]);
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

/// Bits in a timestamp gap: the whole clock, because a delegation family has
/// no lookup channel to range-check into (`docs/spec/delegation.md` §9).
pub const GAP_BITS: usize = mem::TS_BITS as usize;
/// Bits in `(base − RAM_ORIGIN) / 4`, which is below `2^31 / 4`.
pub const BASE_LOW_BITS: usize = 29;
/// Bits in `2^31 − frame bytes − base`.
pub const BASE_ROOM_BITS: usize = 31;

const fn w(i: usize) -> PolyAddress {
    PolyAddress::Witness(i as u32)
}

/// `W[38j + bit]`: bit `bit` of frame word `j`'s timestamp gap.
pub fn gap_bit(j: usize, bit: usize) -> PolyAddress {
    w(GAP_BITS * j + bit)
}

/// `W[38·words + bit]`: bit `bit` of `(base − RAM_ORIGIN) / 4`.
pub fn base_low_bit(words: usize, bit: usize) -> PolyAddress {
    w(GAP_BITS * words + bit)
}

/// `W[38·words + 29 + bit]`: bit `bit` of `2^31 − frame bytes − base`.
pub fn base_room_bit(words: usize, bit: usize) -> PolyAddress {
    w(GAP_BITS * words + BASE_LOW_BITS + bit)
}

/// The first `W` index a family's own columns may take.
pub fn frame_witness(words: usize) -> usize {
    GAP_BITS * words + BASE_LOW_BITS + BASE_ROOM_BITS
}

/// The frame's own `W` column names, in layout order.
pub fn witness_names(words: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(frame_witness(words));
    for j in 0..words {
        for i in 0..GAP_BITS {
            out.push(format!("gap{j}_{i}"));
        }
    }
    for i in 0..BASE_LOW_BITS {
        out.push(format!("base_low{i}"));
    }
    for i in 0..BASE_ROOM_BITS {
        out.push(format!("base_room{i}"));
    }
    out
}

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

pub(crate) fn inner(layer: usize, offset: usize) -> PolyAddress {
    PolyAddress::Inner {
        layer: layer as u32,
        offset: offset as u32,
    }
}

/// `x` unchanged: the pass-through a layered circuit pays to carry a value up.
pub(crate) fn copy(x: PolyAddress) -> GateDef {
    GateDef::Linear {
        terms: vec![(lit(1), x)],
        constant: lit(0),
    }
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
/// no ordinary cycle can produce and which exactly one request may read
/// (`docs/spec/delegation.md` §5).
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
// The frame's bounds
// ---------------------------------------------------------------------------

/// Every gate the frame itself owes, in a fixed order: `live`'s booleanity,
/// one booleanity per gap and base bit, the `words` address rules, the `words`
/// gap decompositions, and the two frame-pointer bounds.
///
/// A gate that must be vacuous on the all-zero padding row carries `live` on
/// every term; one that is already `0 = 0` there stays ungated.
pub(crate) fn frame_gates(space_words: usize, frame_bytes: u64) -> Vec<(String, GateDef)> {
    let words = space_words;
    let mut out: Vec<(String, GateDef)> = Vec::new();
    out.push(("live_boolean".to_string(), booleanity(LIVE)));
    for j in 0..words {
        for i in 0..GAP_BITS {
            out.push((format!("gap{j}_{i}_boolean"), booleanity(gap_bit(j, i))));
        }
    }
    for i in 0..BASE_LOW_BITS {
        out.push((
            format!("base_low{i}_boolean"),
            booleanity(base_low_bit(words, i)),
        ));
    }
    for i in 0..BASE_ROOM_BITS {
        out.push((
            format!("base_room{i}_boolean"),
            booleanity(base_room_bit(words, i)),
        ));
    }
    // `live·(addr_j − base − 4j) = 0`. Gated: on a padding row `addr` and
    // `base` are 0 and `4j` is not.
    for j in 0..words {
        out.push((
            format!("addr_w{j}"),
            quadratic(
                vec![(neg(4 * j as u64), LIVE)],
                vec![
                    (lit(1), LIVE, word(j, WORD_ADDR)),
                    (neg(1), LIVE, BASE),
                ],
            ),
        ));
    }
    // `live·(4·cycle + FRAME_DELTA − 1 − read_ts − Σ 2^i·b_i) = 0`: the read
    // strictly precedes the write, with the gap a sum of 38 booleans rather
    // than two chunks in a table there is no room for.
    for j in 0..words {
        let mut products = vec![
            (lit(mem::TS_STEP), LIVE, CYCLE),
            (neg(1), LIVE, word(j, WORD_READ_TS)),
        ];
        for i in 0..GAP_BITS {
            products.push((neg(1u64 << i), LIVE, gap_bit(j, i)));
        }
        out.push((
            format!("gap_w{j}"),
            GateDef::Quadratic {
                constant: lit(0),
                linear: vec![(
                    Coeff::Literal(
                        Fr::from_u64(constants::delegation::FRAME_DELTA) - Fr::from_u64(1),
                    ),
                    LIVE,
                )],
                products,
            },
        ));
    }
    // `live·(base − RAM_ORIGIN − 4·Σ 2^i·q_i) = 0`: the base is word-aligned
    // and at or above `RAM_ORIGIN`. Over `Fr` 4 is a unit, so alignment is not
    // an equation but a decomposition — a base that is not word-aligned has no
    // witness at all.
    {
        let mut low = vec![(lit(1), LIVE, BASE)];
        for i in 0..BASE_LOW_BITS {
            low.push((neg(4u64 << i), LIVE, base_low_bit(words, i)));
        }
        out.push((
            "base_aligned".to_string(),
            quadratic(vec![(neg(guest_memory::RAM_ORIGIN as u64), LIVE)], low),
        ));
    }
    // `live·((2^31 − frame bytes) − base − Σ 2^i·r_i) = 0`: the whole frame is
    // inside the RAM window.
    {
        let top = (1u64 << 31) - frame_bytes;
        let mut room = vec![(neg(1), LIVE, BASE)];
        for i in 0..BASE_ROOM_BITS {
            room.push((neg(1u64 << i), LIVE, base_room_bit(words, i)));
        }
        out.push((
            "base_in_window".to_string(),
            quadratic(vec![(lit(top), LIVE)], room),
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// Canonical `Fr` values on the frame
// ---------------------------------------------------------------------------

/// Bits a frame value's eight words take: 32 apiece.
pub const VALUE_BITS: usize = 32 * WORDS_PER_VALUE;
/// Bits the canonicity proof of one frame value takes beyond those: eight
/// 32-bit difference limbs and eight borrow bits.
pub const CANONICITY_BITS: usize = 32 * WORDS_PER_VALUE + WORDS_PER_VALUE;
/// Words in one `Fr` on the wire: 32 bytes, little-endian.
pub const WORDS_PER_VALUE: usize = 8;

/// `p` as eight little-endian 32-bit limbs, re-derived from
/// `constants::FR_MODULUS` rather than restated.
pub(crate) fn modulus_limbs() -> [u64; WORDS_PER_VALUE] {
    let mut out = [0u64; WORDS_PER_VALUE];
    for (i, limb) in constants::FR_MODULUS.iter().enumerate() {
        out[2 * i] = limb & 0xffff_ffff;
        out[2 * i + 1] = limb >> 32;
    }
    out
}

/// `2^{32k}` as an `Fr`, the weight of frame word `k` of a value.
pub(crate) fn word_weight(k: usize) -> Fr {
    let mut out = Fr::ONE;
    let radix = Fr::from_u64(1u64 << 32);
    for _ in 0..k {
        out *= radix;
    }
    out
}

/// The eight terms that recompose a frame value from its words, as a linear
/// form over `M`: `Σ 2^{32k}·word(first + k, field)`.
pub(crate) fn value_terms(first: usize, field: u32) -> Vec<(Coeff, PolyAddress)> {
    (0..WORDS_PER_VALUE)
        .map(|k| (Coeff::Literal(word_weight(k)), word(first + k, field)))
        .collect()
}

/// The eight word decompositions and the canonicity proof of one frame value.
///
/// `first` is its first frame word, `field` the field its words are read from
/// (`WORD_READ_VALUE` for an operand, `WORD_WRITE_VALUE` for a result),
/// `bits` the `W` index of its [`VALUE_BITS`] word bits and `canon` the `W`
/// index of its [`CANONICITY_BITS`] difference and borrow bits.
///
/// Two statements, and both are needed. The word gates bound each word below
/// `2^32`, which is what makes the recomposition an integer and what bounds
/// what the invocation writes into RAM. The borrow chain then proves that
/// integer is **below the modulus**: `w_i − p_i − b_{i−1} + 2^32·b_i = d_i`
/// per limb, with every `d_i` below `2^32` and every `b_i` boolean, telescopes
/// to `X − p + 2^256·b_7 = D` over ℤ — every term being a small integer, so
/// the `Fr` equation is the ℤ equation — and `b_7 = 1` puts `X` below `p`.
/// Without it a frame value would have several encodings and the delegated
/// path and the software fallback would disagree on which.
pub(crate) fn canonical_gates(
    name: &str,
    first: usize,
    field: u32,
    bits: usize,
    canon: usize,
) -> Vec<(String, GateDef)> {
    let mut out: Vec<(String, GateDef)> = Vec::new();
    for k in 0..WORDS_PER_VALUE {
        for t in 0..32 {
            out.push((
                format!("{name}_bit{k}_{t}_boolean"),
                booleanity(w(bits + 32 * k + t)),
            ));
        }
    }
    for i in 0..CANONICITY_BITS {
        let which = if i < 32 * WORDS_PER_VALUE {
            format!("diff{}_{}", i / 32, i % 32)
        } else {
            format!("borrow{}", i - 32 * WORDS_PER_VALUE)
        };
        out.push((
            format!("{name}_{which}_boolean"),
            booleanity(w(canon + i)),
        ));
    }
    // `word_k − Σ 2^t·bit = 0`, ungated and degree 1: both sides are 0 on the
    // padding row, so no mask is needed, and this single gate is the word's
    // 32-bit bound and its decode at once.
    for k in 0..WORDS_PER_VALUE {
        let mut terms = vec![(lit(1), word(first + k, field))];
        for t in 0..32 {
            terms.push((neg(1u64 << t), w(bits + 32 * k + t)));
        }
        out.push((format!("{name}_word{k}"), linear(terms)));
    }
    let p = modulus_limbs();
    let borrow = |i: usize| w(canon + 32 * WORDS_PER_VALUE + i);
    for i in 0..WORDS_PER_VALUE {
        let mut lin = vec![(neg(p[i]), LIVE), (lit(1u64 << 32), borrow(i))];
        if i > 0 {
            lin.push((neg(1), borrow(i - 1)));
        }
        for t in 0..32 {
            lin.push((neg(1u64 << t), w(canon + 32 * i + t)));
        }
        out.push((
            format!("{name}_canonical{i}"),
            quadratic(lin, vec![(lit(1), LIVE, word(first + i, field))]),
        ));
    }
    // `b_7 = live`: the subtraction borrowed out, so the value is below `p`.
    out.push((
        format!("{name}_below_modulus"),
        linear(vec![(lit(1), LIVE), (neg(1), borrow(WORDS_PER_VALUE - 1))]),
    ));
    out
}

// ---------------------------------------------------------------------------
// The layered artifact builder
// ---------------------------------------------------------------------------

/// A circuit under construction, layer by layer.
///
/// `crate::build` cannot assemble a circuit whose work needs inner layers of
/// its own — it builds trees and nothing else — and its `push_list` maps an
/// inner address to its scratch slot by searching every slot pushed so far.
/// Here the slot is arithmetic: the slots of a layer are contiguous and in
/// order, so `base[k] + j` is `L{k}[j]`'s. Written from
/// `crates/constraints/src/keccak.rs`'s.
pub(crate) struct Assembly {
    pub(crate) layers: Vec<LayerSpec>,
    pub(crate) relations: Vec<Relation>,
    pub(crate) scratch: Vec<ScratchSlot>,
    /// `base[k]` is the scratch index of `L{k + 1}[0]`.
    base: Vec<u32>,
}

impl Assembly {
    pub(crate) fn new() -> Assembly {
        Assembly {
            layers: Vec::new(),
            relations: Vec::new(),
            scratch: Vec::new(),
            base: Vec::new(),
        }
    }

    /// `L{layer}[offset]`'s scratch slot.
    fn slot_of(&self, address: PolyAddress) -> PolyAddress {
        match address {
            PolyAddress::Inner { layer, offset } => {
                PolyAddress::Scratch(self.base[layer as usize - 1] + offset)
            }
            other => panic!("delegation: {other} is not an inner column"),
        }
    }

    /// The flat spelling of a gate that reads inner columns.
    fn flatten(&self, gate: &GateDef) -> GateDef {
        let mut flat = gate.clone();
        for op in operands_mut(&mut flat) {
            *op = self.slot_of(*op);
        }
        flat
    }

    /// Push gate list `layer − 1`, which writes layer `layer`.
    pub(crate) fn push(
        &mut self,
        layer: usize,
        halving: bool,
        num_vars: u32,
        producing: Vec<(String, GateDef)>,
        enforcing: Vec<(String, GateDef)>,
    ) {
        assert_eq!(layer, self.layers.len() + 1, "delegation: layers go in order");
        self.base.push(self.scratch.len() as u32);
        let reads_inner = layer > 1;
        let mut entries = Vec::with_capacity(producing.len());
        for (j, (name, gate)) in producing.into_iter().enumerate() {
            let flat = if reads_inner {
                self.flatten(&gate)
            } else {
                gate.clone()
            };
            entries.push(ProducingEntry {
                relation: self.relations.len() as u32,
                output: inner(layer, j),
                gate,
            });
            self.relations.push(Relation {
                name: format!("define_{name}"),
                output: Some(self.scratch.len() as u32),
                gate: flat,
            });
            self.scratch.push(ScratchSlot {
                name,
                address: inner(layer, j),
            });
        }
        let mut enforcing_entries = Vec::with_capacity(enforcing.len());
        for (name, gate) in enforcing {
            let flat = if reads_inner {
                self.flatten(&gate)
            } else {
                gate.clone()
            };
            enforcing_entries.push(EnforcingEntry {
                relation: self.relations.len() as u32,
                gate,
            });
            self.relations.push(Relation {
                name,
                output: None,
                gate: flat,
            });
        }
        self.layers.push(LayerSpec {
            halving,
            num_vars,
            width: entries.len() as u32,
            cached: Vec::<CachedEntry>::new(),
            producing: entries,
            enforcing: enforcing_entries,
        });
    }
}

/// Every operand of a gate, mutably. The shapes this module's callers write
/// are `Linear`, `Product`, `Quadratic` and `TreeProduct`; the other three
/// never reach it.
fn operands_mut(gate: &mut GateDef) -> Vec<&mut PolyAddress> {
    match gate {
        GateDef::Linear { terms, .. } => terms.iter_mut().map(|t| &mut t.1).collect(),
        GateDef::Product { left, right, .. } => vec![left, right],
        GateDef::AffineProduct { left, right, .. } => left
            .iter_mut()
            .chain(right.iter_mut())
            .map(|t| &mut t.1)
            .collect(),
        GateDef::TreeProduct { input } => vec![input],
        GateDef::Quadratic {
            linear, products, ..
        } => {
            let mut ops: Vec<&mut PolyAddress> = linear.iter_mut().map(|t| &mut t.1).collect();
            for (_, y, z) in products.iter_mut() {
                ops.push(y);
                ops.push(z);
            }
            ops
        }
        other => panic!("delegation writes no {other:?}"),
    }
}
