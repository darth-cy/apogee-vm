//! The `KECCAK_F` delegation family's circuit: one keccak-f[1600] permutation
//! a row, over the 200-byte frame a delegation request handed over.
//!
//! `docs/spec/delegation.md` is normative: the frame, the anchor, the three
//! request-side zeroings, the round block and the two frame checks. This file
//! is that document as data.
//!
//! ```text
//! M[0]            cycle          the requesting cycle; every write is at 4·cycle + 3
//! M[1]            live           the row mask, and the one mask every leaf carries
//! M[2]            base           the frame base pointer, and the anchor's address
//! M[3]            anchor_value   what the request wrote back on its mirror query
//! M[4 + 4j ..]    frame word j:  addr, read_ts, read_value, write_value
//! W[0..1600]      the input state's bits, bit 64i + z of lane i
//! W[1600..3500]   38 gap bits a frame read, in frame order
//! W[3500..3529]   base = RAM_ORIGIN + 4·Σ 2^k·q_k, 29 bits
//! W[3529..3560]   2^31 − 200 − base = Σ 2^k·r_k, 31 bits
//! ```
//!
//! There is no `S` column, no virtual table and **no lookup channel**: at
//! `2^8` rows no range channel's table fits (`constants::lookup_channel::BITS`
//! bottoms out at 16), so every bound here is a bit decomposition with a
//! booleanity gate — which costs nothing extra in a circuit whose state is
//! already bits, and which makes the 32-bit bound on every word the same gate
//! that reads it (`docs/spec/delegation.md` §9).
//!
//! # The shape, in one paragraph
//!
//! Gate list 0 writes the memory argument's 128 leaves, the 51 columns carried
//! to the top — `live` and the 50 written words — and the first sub-layer of
//! round 0. Twenty-four identical seven-layer blocks then run the permutation,
//! each `theta` over three parity layers and two fold layers, `rho` and `pi`
//! as pure rewiring, and `chi` split in two; `iota` folds into the last gate of
//! its block, an XOR with a constant being affine. The last block's output
//! meets the carried words in 50 enforcing gates, and the memory tree — which
//! has been reducing underneath all along — is all that reaches the halving
//! phase.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::{address_space, challenge_slot, guest_memory, keccak as k, memory as mem};
use field::Fr;

use crate::lookup::ChannelSpec;
use crate::{
    CachedEntry, CircuitArtifact, Coeff, EnforcingEntry, GateDef, LayerSpec, Padding, PolyAddress,
    ProducingEntry, Relation, ScratchSlot, COEFFICIENT_ENCODING_CANONICAL_LE, FORMAT_VERSION,
};

// ---------------------------------------------------------------------------
// The shape
// ---------------------------------------------------------------------------

/// Sub-layers in one round block.
const SUB: usize = 7;
/// Row-wise layers the 24 round blocks occupy: layers 1 through this.
const ROUND_LAYERS: usize = k::ROUNDS * SUB;
/// Leaves a side: the 50 frame words and the anchor, padded to a power of two
/// with leaves that are literally 1.
const LEAVES: usize = 64;
/// Columns the two product trees occupy at layer 1.
const TREE_TOP: usize = 2 * LEAVES;
/// Row-wise lists that reduce the trees to their two roots.
const TREE_DEPTH: usize = 6;
/// Columns carried from layer 1 to the top: `live`, then the 50 written words.
const CARRY: usize = 1 + k::FRAME_WORDS;
/// Bits a timestamp gap is decomposed into.
const GAP_BITS: usize = mem::TS_BITS as usize;
/// Bits of `(base − RAM_ORIGIN) / 4`: `base < RAM_ORIGIN + 2^31`, word-aligned.
const BASE_LOW_BITS: usize = 29;
/// Bits of `2^31 − 200 − base`: the frame's top is inside the RAM window.
const BASE_ROOM_BITS: usize = 31;

/// A frame word's field: the address it reads and writes.
pub const WORD_ADDR: u32 = 0;
/// A frame word's field: the timestamp of the write it reads.
pub const WORD_READ_TS: u32 = 1;
/// A frame word's field: the word before the permutation.
pub const WORD_READ_VALUE: u32 = 2;
/// A frame word's field: the word after it.
pub const WORD_WRITE_VALUE: u32 = 3;

/// `M[0]`: the requesting cycle, which stamps every write the invocation makes.
pub const CYCLE: PolyAddress = PolyAddress::Memory(0);
/// `M[1]`: the row mask. One mask for the whole row — the 50 frame words and
/// the anchor are one invocation, live or not together.
pub const LIVE: PolyAddress = PolyAddress::Memory(1);
/// `M[2]`: the frame base pointer, and the anchor tuple's address.
pub const BASE: PolyAddress = PolyAddress::Memory(2);
/// `M[3]`: the value the request wrote back on its mirror query, which the
/// invocation's teardown tuple reads. Free: the two sides must agree, and an
/// honest fill writes 0 (`docs/spec/delegation.md` §5.2).
pub const ANCHOR_VALUE: PolyAddress = PolyAddress::Memory(3);

/// `M[4 + 4j + field]`: one field of frame word `j`.
pub fn word(j: usize, field: u32) -> PolyAddress {
    PolyAddress::Memory(4 + 4 * j as u32 + field)
}

/// `W[b]`: bit `b` of the input state — bit `z` of lane `i` at `64i + z`.
pub fn in_bit(b: usize) -> PolyAddress {
    PolyAddress::Witness(b as u32)
}

/// `W[1600 + 38j + k]`: bit `k` of frame word `j`'s timestamp gap.
pub fn gap_bit(j: usize, bit: usize) -> PolyAddress {
    PolyAddress::Witness((k::STATE_BITS + GAP_BITS * j + bit) as u32)
}

/// `W[3500 + k]`: bit `k` of `(base − RAM_ORIGIN) / 4`.
pub fn base_low_bit(bit: usize) -> PolyAddress {
    PolyAddress::Witness((k::STATE_BITS + GAP_BITS * k::FRAME_WORDS + bit) as u32)
}

/// `W[3529 + k]`: bit `k` of `2^31 − 200 − base`.
pub fn base_room_bit(bit: usize) -> PolyAddress {
    PolyAddress::Witness((k::STATE_BITS + GAP_BITS * k::FRAME_WORDS + BASE_LOW_BITS + bit) as u32)
}

/// How many `M` columns the family commits.
pub const MEMORY_COLUMNS: usize = 4 + 4 * k::FRAME_WORDS;
/// How many `W` columns the family commits.
pub const WITNESS_COLUMNS: usize =
    k::STATE_BITS + GAP_BITS * k::FRAME_WORDS + BASE_LOW_BITS + BASE_ROOM_BITS;

/// The bit index of lane `(x, y)`'s bit `z`: lane `5y + x`, bit `z`.
fn bit(x: usize, y: usize, z: usize) -> usize {
    k::LANE_BITS * (x + 5 * y) + z
}

/// The state bit whose value `rho` and `pi` place at `(X, Y, Z)`.
///
/// The forward map is `B[y][2x + 3y] = rot(A[x][y], r[x][y])`, so `(X, Y)`
/// reads the lane at `y = X` and `x = 3Y + X mod 5` — the inverse of
/// `2x + 3y ≡ Y` — and `Z` reads bit `Z − r[x][y]`, a rotate being a
/// relabelling of positions.
fn rho_pi_source(big_x: usize, big_y: usize, big_z: usize) -> usize {
    let x = (3 * big_y + big_x) % 5;
    let y = big_x;
    let rho = k::ROTATIONS[y][x] as usize % k::LANE_BITS;
    bit(x, y, (big_z + k::LANE_BITS - rho) % k::LANE_BITS)
}

// ---------------------------------------------------------------------------
// Gate constructors
// ---------------------------------------------------------------------------

fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

fn neg(v: u64) -> Coeff {
    Coeff::Literal(-Fr::from_u64(v))
}

fn slot(s: u32) -> Coeff {
    Coeff::Challenge(s)
}

fn inner(layer: usize, offset: usize) -> PolyAddress {
    PolyAddress::Inner {
        layer: layer as u32,
        offset: offset as u32,
    }
}

/// `x` unchanged: the pass-through a layered circuit pays to carry a value up.
fn copy(x: PolyAddress) -> GateDef {
    GateDef::Linear {
        terms: vec![(lit(1), x)],
        constant: lit(0),
    }
}

/// `x + y − 2xy`, the XOR of two bits.
fn xor(x: PolyAddress, y: PolyAddress) -> GateDef {
    GateDef::Quadratic {
        constant: lit(0),
        linear: vec![(lit(1), x), (lit(1), y)],
        products: vec![(neg(2), x, y)],
    }
}

/// `x − x·x`, which holds exactly at `x ∈ {0, 1}`.
fn booleanity(x: PolyAddress) -> GateDef {
    GateDef::Quadratic {
        constant: lit(0),
        linear: vec![(lit(1), x)],
        products: vec![(neg(1), x, x)],
    }
}

fn quadratic(
    linear: Vec<(Coeff, PolyAddress)>,
    products: Vec<(Coeff, PolyAddress, PolyAddress)>,
) -> GateDef {
    GateDef::Quadratic {
        constant: lit(0),
        linear,
        products,
    }
}

/// One memory leaf: `live·T(space, addr, ts, value) + 1 − live`, written flat
/// as `docs/spec/memory.md` §2.2 writes one.
///
/// `ts` is `None` for the anchor's answer tuple, whose timestamp is the
/// literal 0 — the stamp no ordinary cycle can produce — and `Some` otherwise,
/// carrying either a column read or `4·cycle + 3`. `value` is `None` for the
/// answer tuple too, whose value is the literal 0.
fn leaf(
    space: u8,
    addr: PolyAddress,
    ts: Timestamp,
    value: Option<PolyAddress>,
) -> GateDef {
    let mut linear = vec![
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
                linear.push((slot(challenge_slot::MEM_ALPHA_TS), LIVE));
            }
        }
    }
    if let Some(value) = value {
        products.push((slot(challenge_slot::MEM_ALPHA_VAL), value, LIVE));
    }
    GateDef::Quadratic {
        constant: lit(1),
        linear,
        products,
    }
}

/// A leaf's timestamp: the literal 0, a column, or this row's
/// `4·cycle + delta`.
enum Timestamp {
    Zero,
    Column(PolyAddress),
    Write(u64),
}

/// A leaf that is the product's identity: a family whose query count is not a
/// power of two pays inner columns for these and nothing else.
fn pad_leaf() -> GateDef {
    GateDef::Linear {
        terms: Vec::new(),
        constant: lit(1),
    }
}

// ---------------------------------------------------------------------------
// The layer geometry
// ---------------------------------------------------------------------------

/// Layer `k`'s memory-tree columns: the leaf level halves once per row-wise
/// list until the two roots remain, which are then copied up to the halving
/// phase.
fn tree_width(k: usize) -> usize {
    if k <= TREE_DEPTH {
        TREE_TOP >> (k - 1)
    } else {
        2
    }
}

/// Layer `k`'s carried columns: `live` and the 50 written words, which the top
/// of the permutation needs and which only gate list 0 could read.
fn carry_width(k: usize) -> usize {
    if k <= ROUND_LAYERS {
        CARRY
    } else {
        0
    }
}

/// Layer `k`'s permutation columns, by the sub-layer of its round block.
fn keccak_width(k: usize) -> usize {
    if k == 0 || k > ROUND_LAYERS {
        return 0;
    }
    match (k - 1) % SUB {
        0 => 2 * 5 * k::LANE_BITS + k::STATE_BITS, // p0, p1, A
        1 | 2 => 5 * k::LANE_BITS + k::STATE_BITS, // q or c, A
        3 => k::STATE_BITS + 5 * k::LANE_BITS,     // u, c
        4 => k::STATE_BITS,                        // b
        5 => 2 * k::STATE_BITS,                    // v, B'
        _ => k::STATE_BITS,                        // the round's output
    }
}

/// Layer `k`'s memory-tree column `i`.
fn tree(k: usize, i: usize) -> PolyAddress {
    inner(k, i)
}

/// Layer `k`'s carried column `i`: 0 is `live`, `1 + j` is written word `j`.
fn carry(k: usize, i: usize) -> PolyAddress {
    inner(k, tree_width(k) + i)
}

/// Layer `k`'s permutation column `i`.
fn kec(k: usize, i: usize) -> PolyAddress {
    inner(k, tree_width(k) + carry_width(k) + i)
}

/// Round `r`'s input state bit `b`: the committed bits for round 0, and the
/// previous round's output above it.
fn round_input(r: usize, b: usize) -> PolyAddress {
    if r == 0 {
        in_bit(b)
    } else {
        kec(SUB * r, b)
    }
}

// ---------------------------------------------------------------------------
// The assembly
// ---------------------------------------------------------------------------

/// The artifact as it is built: the gate lists, the flat relation list and the
/// scratch bijection, kept in step.
///
/// `crate::build` cannot assemble this circuit — it builds trees and nothing
/// else — and its `push_list` maps an inner address to its scratch slot by
/// searching every slot pushed so far, which is quadratic in a circuit of this
/// width. Here the slot is arithmetic: the slots of a layer are contiguous and
/// in order, so `base[k] + j` is `L{k}[j]`'s.
struct Assembly {
    layers: Vec<LayerSpec>,
    relations: Vec<Relation>,
    scratch: Vec<ScratchSlot>,
    /// `base[k]` is the scratch index of `L{k + 1}[0]`.
    base: Vec<u32>,
}

impl Assembly {
    fn new() -> Assembly {
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
            other => panic!("keccak: {other} is not an inner column"),
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
    fn push(
        &mut self,
        layer: usize,
        halving: bool,
        num_vars: u32,
        producing: Vec<(String, GateDef)>,
        enforcing: Vec<(String, GateDef)>,
    ) {
        assert_eq!(layer, self.layers.len() + 1, "keccak: layers go in order");
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

/// Every operand of a gate, mutably. The shapes this file writes are `Linear`,
/// `Product`, `Quadratic` and `TreeProduct`; the other three never reach it.
fn operands_mut(gate: &mut GateDef) -> Vec<&mut PolyAddress> {
    match gate {
        GateDef::Linear { terms, .. } => terms.iter_mut().map(|t| &mut t.1).collect(),
        GateDef::Product { left, right, .. } => vec![left, right],
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
        other => panic!("keccak writes no {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Gate list 0
// ---------------------------------------------------------------------------

/// The memory argument's leaves, read side then write side, each padded to
/// `LEAVES` with the product's identity.
fn leaves() -> Vec<(String, GateDef)> {
    let mut out: Vec<(String, GateDef)> = Vec::with_capacity(TREE_TOP);
    for j in 0..k::FRAME_WORDS {
        out.push((
            format!("read_w{j}"),
            leaf(
                address_space::RAM,
                word(j, WORD_ADDR),
                Timestamp::Column(word(j, WORD_READ_TS)),
                Some(word(j, WORD_READ_VALUE)),
            ),
        ));
    }
    // The invocation's teardown: it consumes what the request wrote back on
    // its mirror query, which binds the request's cycle to this row's
    // (`docs/spec/delegation.md` §5.3).
    out.push((
        "read_anchor".to_string(),
        leaf(
            address_space::DELEGATION_KECCAK_F,
            BASE,
            Timestamp::Write(constants::delegation::ANCHOR_DELTA),
            Some(ANCHOR_VALUE),
        ),
    ));
    for i in 0..LEAVES - k::FRAME_WORDS - 1 {
        out.push((format!("read_pad{i}"), pad_leaf()));
    }
    for j in 0..k::FRAME_WORDS {
        out.push((
            format!("write_w{j}"),
            leaf(
                address_space::RAM,
                word(j, WORD_ADDR),
                Timestamp::Write(constants::delegation::FRAME_DELTA),
                Some(word(j, WORD_WRITE_VALUE)),
            ),
        ));
    }
    // The answer tuple, stamped 0. Nothing else in this address space writes
    // one, so a request's read of it is a request paired with an invocation.
    out.push((
        "write_anchor".to_string(),
        leaf(
            address_space::DELEGATION_KECCAK_F,
            BASE,
            Timestamp::Zero,
            None,
        ),
    ));
    for i in 0..LEAVES - k::FRAME_WORDS - 1 {
        out.push((format!("write_pad{i}"), pad_leaf()));
    }
    out
}

/// Gate list 0's enforcing gates: the row mask, every bit's booleanity, the
/// frame's addressing, its gap bounds, its input recomposition and the two
/// frame-pointer checks.
fn list0_enforcing() -> Vec<(String, GateDef)> {
    let mut out: Vec<(String, GateDef)> = Vec::new();
    out.push(("live_boolean".to_string(), booleanity(LIVE)));
    for b in 0..k::STATE_BITS {
        out.push((format!("in_bit{b}_boolean"), booleanity(in_bit(b))));
    }
    for j in 0..k::FRAME_WORDS {
        for i in 0..GAP_BITS {
            out.push((
                format!("gap{j}_{i}_boolean"),
                booleanity(gap_bit(j, i)),
            ));
        }
    }
    for i in 0..BASE_LOW_BITS {
        out.push((
            format!("base_low{i}_boolean"),
            booleanity(base_low_bit(i)),
        ));
    }
    for i in 0..BASE_ROOM_BITS {
        out.push((
            format!("base_room{i}_boolean"),
            booleanity(base_room_bit(i)),
        ));
    }
    // Frame word `j` is at `base + 4j`: one memory, and one pointer.
    for j in 0..k::FRAME_WORDS {
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
    // The timestamp gap of every read, `docs/spec/memory.md` §2.4's statement
    // over 38 bits rather than its 19+19 lookup: `gap = 4·cycle + 3 − read_ts
    // − 1` is in `[0, 2^38)` because it is a sum of 38 booleans.
    for j in 0..k::FRAME_WORDS {
        let mut products = vec![
            (lit(mem::TS_STEP), LIVE, CYCLE),
            (neg(1), LIVE, word(j, WORD_READ_TS)),
        ];
        for i in 0..GAP_BITS {
            products.push((neg(1u64 << i), LIVE, gap_bit(j, i)));
        }
        // `4·cycle + FRAME_DELTA − read_ts − 1`, and `FRAME_DELTA` is 0, so
        // the constant is `−live`.
        out.push((
            format!("gap_w{j}"),
            quadratic(
                vec![(
                    Coeff::Literal(
                        Fr::from_u64(constants::delegation::FRAME_DELTA) - Fr::from_u64(1),
                    ),
                    LIVE,
                )],
                products,
            ),
        ));
    }
    // Every word the invocation reads is its 32 input bits, which is also the
    // only bound those words need: a sum of 32 booleans is below `2^32`.
    for j in 0..k::FRAME_WORDS {
        let mut terms = vec![(lit(1), word(j, WORD_READ_VALUE))];
        for t in 0..32 {
            terms.push((neg(1u64 << t), in_bit(word_bit(j, t))));
        }
        out.push((
            format!("input_w{j}"),
            GateDef::Linear {
                terms,
                constant: lit(0),
            },
        ));
    }
    // The frame pointer: word-aligned and at or above `RAM_ORIGIN` by the
    // first decomposition, and with the whole frame below `2^31` by the
    // second. Both are in the artifact and neither is an assumption.
    let mut low = vec![(lit(1), LIVE, BASE)];
    for i in 0..BASE_LOW_BITS {
        low.push((neg(4u64 << i), LIVE, base_low_bit(i)));
    }
    out.push((
        "base_aligned".to_string(),
        quadratic(
            vec![(neg(guest_memory::RAM_ORIGIN as u64), LIVE)],
            low,
        ),
    ));
    let top = (1u64 << 31) - k::STATE_BYTES as u64;
    let mut room = vec![(neg(1), LIVE, BASE)];
    for i in 0..BASE_ROOM_BITS {
        room.push((neg(1u64 << i), LIVE, base_room_bit(i)));
    }
    out.push((
        "base_in_window".to_string(),
        quadratic(vec![(lit(top), LIVE)], room),
    ));
    out
}

/// Bit `t` of frame word `j`: word `2i + h` is lane `i`'s half `h`.
fn word_bit(j: usize, t: usize) -> usize {
    k::LANE_BITS * (j / 2) + 32 * (j % 2) + t
}

// ---------------------------------------------------------------------------
// One round block
// ---------------------------------------------------------------------------

/// The permutation columns gate list `SUB·r + sub` writes.
///
/// `sub` is the sub-layer within round `r`, `0..SUB`; the list reads layer
/// `SUB·r + sub` and writes the next. `docs/spec/delegation.md` §6 is the
/// block, gate for gate.
fn round_sub(r: usize, sub: usize) -> Vec<(String, GateDef)> {
    let read = SUB * r + sub;
    let mut out: Vec<(String, GateDef)> = Vec::new();
    let name = |tag: &str, i: usize| format!("r{r}_{}_{tag}_{i}", sub + 1);
    match sub {
        // theta, level 1: the parity tree's first two pairs, and the state.
        0 => {
            for x in 0..5 {
                for z in 0..k::LANE_BITS {
                    out.push((
                        name("p0", k::LANE_BITS * x + z),
                        xor(round_input(r, bit(x, 0, z)), round_input(r, bit(x, 1, z))),
                    ));
                }
            }
            for x in 0..5 {
                for z in 0..k::LANE_BITS {
                    out.push((
                        name("p1", k::LANE_BITS * x + z),
                        xor(round_input(r, bit(x, 2, z)), round_input(r, bit(x, 3, z))),
                    ));
                }
            }
            for b in 0..k::STATE_BITS {
                out.push((name("a", b), copy(round_input(r, b))));
            }
        }
        // theta, level 2.
        1 => {
            for x in 0..5 {
                for z in 0..k::LANE_BITS {
                    let i = k::LANE_BITS * x + z;
                    out.push((
                        name("q", i),
                        xor(kec(read, i), kec(read, 5 * k::LANE_BITS + i)),
                    ));
                }
            }
            for b in 0..k::STATE_BITS {
                out.push((name("a", b), copy(kec(read, 2 * 5 * k::LANE_BITS + b))));
            }
        }
        // theta, level 3: the column parity C.
        2 => {
            for x in 0..5 {
                for z in 0..k::LANE_BITS {
                    let i = k::LANE_BITS * x + z;
                    out.push((
                        name("c", i),
                        xor(
                            kec(read, i),
                            kec(read, 5 * k::LANE_BITS + bit(x, 4, z)),
                        ),
                    ));
                }
            }
            for b in 0..k::STATE_BITS {
                out.push((name("a", b), copy(kec(read, 5 * k::LANE_BITS + b))));
            }
        }
        // theta's first fold: A ⊕ C[x−1]. The loops run `y` outside `x` so a
        // column's offset is `bit(x, y, z)`, which is what every reader of
        // this layer uses; an x-major push would transpose the state.
        3 => {
            for y in 0..5 {
                for x in 0..5 {
                    for z in 0..k::LANE_BITS {
                        let c = k::LANE_BITS * ((x + 4) % 5) + z;
                        out.push((
                            name("u", bit(x, y, z)),
                            xor(
                                kec(read, 5 * k::LANE_BITS + bit(x, y, z)),
                                kec(read, c),
                            ),
                        ));
                    }
                }
            }
            for i in 0..5 * k::LANE_BITS {
                out.push((name("c", i), copy(kec(read, i))));
            }
        }
        // theta's second fold: ⊕ rot(C[x+1], 1). The state is now B. `y`
        // outside `x`, for the same reason sub-layer 3's loops are.
        4 => {
            for y in 0..5 {
                for x in 0..5 {
                    for z in 0..k::LANE_BITS {
                        let c = k::LANE_BITS * ((x + 1) % 5)
                            + (z + k::LANE_BITS - 1) % k::LANE_BITS;
                        out.push((
                            name("b", bit(x, y, z)),
                            xor(
                                kec(read, bit(x, y, z)),
                                kec(read, k::STATE_BITS + c),
                            ),
                        ));
                    }
                }
            }
        }
        // chi, step 1, and B rewired: rho and pi are addressing and cost
        // nothing but the pass-through B' already owes chi's second step.
        5 => {
            for big_y in 0..5 {
                for big_x in 0..5 {
                    for big_z in 0..k::LANE_BITS {
                        let one = rho_pi_source((big_x + 1) % 5, big_y, big_z);
                        let two = rho_pi_source((big_x + 2) % 5, big_y, big_z);
                        out.push((
                            name("v", bit(big_x, big_y, big_z)),
                            GateDef::Product {
                                coeff: lit(1),
                                left: kec(read, one),
                                right: kec(read, two),
                            },
                        ));
                    }
                }
            }
            for big_y in 0..5 {
                for big_x in 0..5 {
                    for big_z in 0..k::LANE_BITS {
                        out.push((
                            name("bp", bit(big_x, big_y, big_z)),
                            copy(kec(read, rho_pi_source(big_x, big_y, big_z))),
                        ));
                    }
                }
            }
        }
        // chi, step 2, with iota folded in: `A' = B ⊕ (B2 − B1·B2)`, and on
        // lane (0,0) `⊕ RC`, which is affine and so free.
        _ => {
            for big_y in 0..5 {
                for big_x in 0..5 {
                    for big_z in 0..k::LANE_BITS {
                        let here = bit(big_x, big_y, big_z);
                        let two = bit((big_x + 2) % 5, big_y, big_z);
                        let bp = |i: usize| kec(read, k::STATE_BITS + i);
                        let v = kec(read, here);
                        let mut linear =
                            vec![(lit(1), bp(here)), (lit(1), bp(two)), (neg(1), v)];
                        let mut products =
                            vec![(neg(2), bp(here), bp(two)), (lit(2), bp(here), v)];
                        let mut constant = lit(0);
                        if big_x == 0
                            && big_y == 0
                            && (k::ROUND_CONSTANTS[r] >> big_z) & 1 == 1
                        {
                            // `g ⊕ 1 = 1 − g`: negate the gate and add one.
                            for t in linear.iter_mut() {
                                t.0 = negate(t.0);
                            }
                            for t in products.iter_mut() {
                                t.0 = negate(t.0);
                            }
                            constant = lit(1);
                        }
                        out.push((
                            name("out", here),
                            GateDef::Quadratic {
                                constant,
                                linear,
                                products,
                            },
                        ));
                    }
                }
            }
        }
    }
    out
}

fn negate(c: Coeff) -> Coeff {
    match c {
        Coeff::Literal(v) => Coeff::Literal(-v),
        Coeff::Challenge(_) => panic!("keccak: a round gate carries no challenge"),
    }
}

// ---------------------------------------------------------------------------
// The artifact
// ---------------------------------------------------------------------------

/// The family's circuit over `2^trace_vars` rows.
///
/// Panics on every refusal of `validate` and of `memory::check_memory`, and if
/// the counted shape is not `docs/spec/delegation.md`'s.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    let mut a = Assembly::new();

    // Gate list 0: the leaves, the carried columns, and round 0's first
    // sub-layer.
    let mut producing = leaves();
    producing.push(("live_1".to_string(), copy(LIVE)));
    for j in 0..k::FRAME_WORDS {
        producing.push((format!("wv{j}_1"), copy(word(j, WORD_WRITE_VALUE))));
    }
    producing.extend(round_sub(0, 0));
    a.push(1, false, trace_vars, producing, list0_enforcing());

    // The round blocks, with the memory tree reducing and the carry rising
    // beneath them.
    for layer in 1..=ROUND_LAYERS {
        let mut producing: Vec<(String, GateDef)> = Vec::new();
        let width = tree_width(layer);
        if width > 2 {
            for i in 0..width / 2 {
                producing.push((
                    format!("mtree{layer}_{i}"),
                    GateDef::Product {
                        coeff: lit(1),
                        left: tree(layer, 2 * i),
                        right: tree(layer, 2 * i + 1),
                    },
                ));
            }
        } else {
            for (i, side) in ["read", "write"].iter().enumerate() {
                producing.push((format!("{side}_up{layer}"), copy(tree(layer, i))));
            }
        }
        if layer < ROUND_LAYERS {
            producing.push((format!("live_{}", layer + 1), copy(carry(layer, 0))));
            for j in 0..k::FRAME_WORDS {
                producing.push((
                    format!("wv{j}_{}", layer + 1),
                    copy(carry(layer, 1 + j)),
                ));
            }
        }
        let enforcing = if layer == ROUND_LAYERS {
            output_gates(layer)
        } else {
            producing.extend(round_sub(layer / SUB, layer % SUB));
            Vec::new()
        };
        a.push(layer + 1, false, trace_vars, producing, enforcing);
    }

    // The halving phase: the two roots down to a zero-variable top.
    for step in 0..trace_vars {
        let layer = ROUND_LAYERS + 2 + step as usize;
        let producing = (0..2)
            .map(|i| {
                let side = if i == 0 { "read" } else { "write" };
                // The top layer's two columns are the roots
                // `docs/spec/memory.md` §1 names.
                let name = if step + 1 == trace_vars {
                    format!("{side}_root")
                } else {
                    format!("{side}_h{step}")
                };
                (
                    name,
                    GateDef::TreeProduct {
                        input: inner(layer - 1, i),
                    },
                )
            })
            .collect();
        a.push(layer, true, trace_vars - step - 1, producing, Vec::new());
    }

    let top = ROUND_LAYERS + 1 + trace_vars as usize;
    let memory: Vec<String> = memory_names();
    let witness: Vec<String> = witness_names();
    let committed = memory.len() + witness.len();
    let artifact = CircuitArtifact {
        format_version: FORMAT_VERSION,
        coefficient_encoding: COEFFICIENT_ENCODING_CANONICAL_LE,
        trace_vars,
        memory,
        witness,
        setup: Vec::new(),
        virtuals: Vec::new(),
        layers: a.layers,
        relations: a.relations,
        lookups: Vec::new(),
        scratch: a.scratch,
        outputs: vec![inner(top, mem::READ_ROOT), inner(top, mem::WRITE_ROOT)],
        padding: Padding {
            row: vec![Fr::ZERO; committed],
            // Every enforcing gate is a sum of terms carrying `live`, a
            // booleanity, or the input recomposition, and each is 0 where
            // every committed cell is; the product tree's leaves are then all
            // 1, which is the padding contract's second clause.
            zero_row_valid: true,
        },
    };
    if let Err(e) = artifact.validate() {
        panic!("keccak: the assembled circuit is not a circuit: {e}");
    }
    if let Err(e) = crate::memory::check_memory(&artifact) {
        panic!("keccak: {e}");
    }
    check_shape(&artifact);
    artifact
}

/// The last list's enforcing gates: every written word is the permutation's
/// output bits, gated on the row's liveness.
///
/// Gated, because a padding row's committed cells are zero and keccak-f of the
/// zero state is not: the circuit computes it there, and without `live` the
/// gate would ask the written word to be it.
fn output_gates(layer: usize) -> Vec<(String, GateDef)> {
    let live = carry(layer, 0);
    (0..k::FRAME_WORDS)
        .map(|j| {
            let mut products = vec![(lit(1), live, carry(layer, 1 + j))];
            for t in 0..32 {
                products.push((neg(1u64 << t), live, kec(layer, word_bit(j, t))));
            }
            (format!("output_w{j}"), quadratic(Vec::new(), products))
        })
        .collect()
}

fn memory_names() -> Vec<String> {
    let mut out = vec![
        "cycle".to_string(),
        "live".to_string(),
        "base".to_string(),
        "anchor_value".to_string(),
    ];
    for j in 0..k::FRAME_WORDS {
        for field in ["addr", "read_ts", "read_value", "write_value"] {
            out.push(format!("w{j}_{field}"));
        }
    }
    out
}

fn witness_names() -> Vec<String> {
    let mut out: Vec<String> = (0..k::STATE_BITS).map(|b| format!("in_bit{b}")).collect();
    for j in 0..k::FRAME_WORDS {
        for i in 0..GAP_BITS {
            out.push(format!("gap{j}_{i}"));
        }
    }
    out.extend((0..BASE_LOW_BITS).map(|i| format!("base_low{i}")));
    out.extend((0..BASE_ROOM_BITS).map(|i| format!("base_room{i}")));
    out
}

/// The counted shape, on the finished artifact rather than on what was handed
/// in: S21 must-be-exact 4's rule, and the only thing that shows an alignment
/// or a bound check reached the emitted circuit.
fn check_shape(a: &CircuitArtifact) {
    // Every layer's width is its three parts', which is what the offset
    // helpers assume when they read a column: `tree(k, i)`, `carry(k, i)` and
    // `kec(k, i)` all index off `tree_width(k)` and `carry_width(k)`, and a
    // layer one column wider or narrower than they think would read a
    // neighbour's column with no other symptom.
    for (k, list) in a.layers.iter().enumerate() {
        if list.halving {
            continue;
        }
        let want = tree_width(k + 1) + carry_width(k + 1) + keccak_width(k + 1);
        assert_eq!(
            list.width as usize,
            want,
            "keccak: layer {} is {} columns, not {want}",
            k + 1,
            list.width
        );
    }
    assert_eq!(
        a.memory.len(),
        MEMORY_COLUMNS,
        "keccak: {} memory columns, not {MEMORY_COLUMNS}",
        a.memory.len()
    );
    assert_eq!(
        a.witness.len(),
        WITNESS_COLUMNS,
        "keccak: {} witness columns, not {WITNESS_COLUMNS}",
        a.witness.len()
    );
    assert!(a.setup.is_empty(), "keccak: the family has no setup column");
    assert!(
        a.lookups.is_empty(),
        "keccak: the family carries no lookup channel; its bounds are bit decompositions"
    );
    assert_eq!(
        a.layers.len(),
        ROUND_LAYERS + 1 + a.trace_vars as usize,
        "keccak: the depth is the 24 round blocks, the output list and the halving phase"
    );
    let want = 1
        + k::STATE_BITS
        + GAP_BITS * k::FRAME_WORDS
        + BASE_LOW_BITS
        + BASE_ROOM_BITS
        + 3 * k::FRAME_WORDS
        + 2;
    assert_eq!(
        a.layers[0].enforcing.len(),
        want,
        "keccak: gate list 0 carries {} enforcing gates, not {want}",
        a.layers[0].enforcing.len()
    );
    // The two frame-pointer checks by name, and the per-word ones by count:
    // an `assume_*` hypothesis is exactly what a name check refuses to stand
    // in for (S21 must-be-exact 4).
    for name in ["base_aligned", "base_in_window"] {
        assert!(
            a.relations.iter().any(|r| r.name == name),
            "keccak: the artifact has no `{name}` gate"
        );
    }
    for (prefix, want) in [
        ("addr_w", k::FRAME_WORDS),
        ("gap_w", k::FRAME_WORDS),
        ("input_w", k::FRAME_WORDS),
        ("output_w", k::FRAME_WORDS),
    ] {
        let got = a
            .relations
            .iter()
            .filter(|r| r.name.starts_with(prefix) && r.output.is_none())
            .count();
        assert_eq!(got, want, "keccak: {got} `{prefix}` gates, not {want}");
    }
    assert_eq!(
        a.layers[ROUND_LAYERS].enforcing.len(),
        k::FRAME_WORDS,
        "keccak: the output list carries one gate per frame word"
    );
}

/// The family's channels: none.
///
/// A delegation family at `2^8` rows cannot carry one — `V[range16]` over 8
/// variables holds `[0, 2^8)`, not `[0, 2^16)` — so every bound this circuit
/// makes is a bit decomposition with a booleanity gate of its own
/// (`docs/spec/delegation.md` §9).
pub fn channels() -> Vec<ChannelSpec> {
    Vec::new()
}
