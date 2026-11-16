//! The `MERKLE_ROOT` precompile, `docs/spec/precompiles.md` §6: a path's root
//! from its leaf, its slot and its `16..=32` siblings, as three circuits on
//! `crate::delegation`'s builder.
//!
//! - `MERKLE_ROOT`, one row a call: the frame's 19 words, the leaf sent as
//!   boundary 0 with the control `(slot, siblings)`, the root received as
//!   boundary `16·depth` with the control `(0, siblings + 64·depth)`, and the
//!   root written canonical over the leaf.
//! - `MERKLE_LEVELS`, one row a level `L`: the node and the control received,
//!   the sibling's 16 words read from RAM, the slot's bit taken, and the two
//!   in order through `M_E` sent as boundary `16L + 1`, the next control
//!   beside it.
//! - `MERKLE_ROUNDS`, sixteen rows a level: `POSEIDON2_ROUNDS`' rows
//!   (`crate::poseidon2::rounds`) from boundary `16L + 1` to `16(L + 1)`, the
//!   last writing only the node, the first eight lanes.
//!
//! The call at `cycle` keeps its state in `address_space::MERKLE`: lane pair
//! `s` at boundary `B` is `(MERKLE, cycle, 16B + s, lane 2s, lane 2s + 1)`,
//! and the control at level `L`'s boundary `(MERKLE, cycle, 256L + 8, rest,
//! ptr)`, `rest` the slot's bits not yet taken and `ptr` the level's sibling.
//! Every row's stamp is bounded, so a timestamp is one boundary and one slot.

use alloc::format;
use alloc::vec::Vec;

use constants::delegation::merkle::{
    DEPTH, FRAME, LANES, MAX_DEPTH, MIN_DEPTH, SIBLING, SIBLINGS, SLOT,
};
use constants::{address_space, ecall, family};
use field::Fp;

use crate::delegation::{access, frame, Builder, Part};
use crate::family::{Expr, T32};
use crate::lookup::ChannelSpec;
use crate::poseidon2::{canonical, external_entry, rounds, Keyed};
use crate::{CircuitArtifact, PolyAddress};

/// Timestamps a boundary takes: its eight lane pairs, then the control at
/// [`CONTROL`].
pub const STRIDE: u64 = 16;
/// The control's slot in a level's boundary.
pub const CONTROL: u64 = 8;
/// Timestamps a level takes: sixteen boundaries, its level row's and its
/// fifteen rounds'.
pub const LEVEL: u64 = 16 * STRIDE;
/// Lane pairs a node is, a digest's eight lanes.
pub const NODE_PAIRS: usize = 4;

/// `1/LEVEL`: what takes a stamp's `LEVEL·L` to its level, bounded.
pub fn per_level() -> Fp {
    Fp::from_u64(LEVEL).inverse().expect("256 is a unit")
}

/// A state tuple of the call at `cycle`: `(MERKLE, cycle, at, x, y)`.
fn tuple(cycle: PolyAddress, at: Part, x: Part, y: Part) -> [Part; 4] {
    [Part::of(cycle), at, x, y]
}

/// `MERKLE_ROOT`: the frame, the depth in range, the leaf and the slot sent,
/// the root and the spent slot received, the root written canonical.
///
/// ```text
/// depth_low     depth − 16 < 2^16                depth_high   32 − depth < 2^16
/// last_rule     last − 256·depth                 the root's boundary 16·depth
/// end_rule      end − siblings − 64·depth        the control the last level writes
/// n{i}_rule     n_i − read_{2i} − 2^32·read_{2i+1}     the leaf, read mod p
/// o{l}          canonical(o_l; write_{2l}, write_{2l+1})   the root
/// send     (cycle, s, n_2s, n_2s+1), s < 4        (cycle, 8, slot, siblings)
/// receive  (cycle, last + s, o_2s, o_2s+1)        (cycle, last + 8, 0, end)
/// ```
///
/// The control received holds `rest = 0`: every bit of the slot was taken
/// within `depth` levels, so the slot is below `2^depth`.
fn frame_row() -> Builder {
    let mut b = Builder::new(family::MERKLE_ROOT);
    let live = b.live;
    let f = frame(&mut b, ecall::MERKLE_ROOT, FRAME, |j| j < LANES);
    let (slot, depth, siblings) = (
        f.words[SLOT].read,
        f.words[DEPTH].read,
        f.words[SIBLINGS].read,
    );
    b.range16("depth_low", depth - live * MIN_DEPTH as u64);
    b.range16("depth_high", live * MAX_DEPTH as u64 - depth);
    let last = b.mcol("last");
    b.gate("last_rule", last - depth * LEVEL);
    let end = b.mcol("end");
    b.gate("end_rule", end - siblings - depth * (4 * SIBLING as u64));
    let n: Vec<PolyAddress> = (0..8).map(|i| b.mcol(&format!("n{i}"))).collect();
    let o: Vec<PolyAddress> = (0..8).map(|l| b.mcol(&format!("o{l}"))).collect();
    for (i, ni) in n.iter().enumerate() {
        let (lo, hi) = (f.words[2 * i].read, f.words[2 * i + 1].read);
        b.gate(&format!("n{i}_rule"), *ni - lo - hi * T32);
    }
    for (l, ol) in o.iter().enumerate() {
        let (lo, hi) = (f.words[2 * l].write, f.words[2 * l + 1].write);
        canonical(&mut b, &format!("o{l}"), *ol, lo, hi);
    }
    let space = address_space::MERKLE;
    for s in 0..NODE_PAIRS {
        let at = s as u64;
        let leaf = tuple(
            f.cycle,
            Part::constant(at),
            Part::of(n[2 * s]),
            Part::of(n[2 * s + 1]),
        );
        b.leaf(true, &format!("send_n{s}"), space, leaf);
        let root = tuple(
            f.cycle,
            Part::plus(last, at),
            Part::of(o[2 * s]),
            Part::of(o[2 * s + 1]),
        );
        b.leaf(false, &format!("receive_o{s}"), space, root);
    }
    let start = tuple(
        f.cycle,
        Part::constant(CONTROL),
        Part::of(slot),
        Part::of(siblings),
    );
    b.leaf(true, "send_control", space, start);
    let spent = tuple(
        f.cycle,
        Part::plus(last, CONTROL),
        Part::default(),
        Part::of(end),
    );
    b.leaf(false, "receive_control", space, spent);
    b
}

/// `MERKLE_LEVELS`: level `L` of the call at `cycle`, its stamp `256L`.
///
/// ```text
/// level_range   stamp/256 < 2^16                 next_rule   next − stamp − 256
/// rest_rule     rest − bit − 2·rest_next         bit boolean: the slot's bit L
/// u{j}_rule     u_j − Σ_k M_E[j][k]·n_k − M_E[j][8 + k]·s_k
///                   − bit·Σ_k (M_E[j][k] − M_E[j][8 + k])·(s_k − n_k)
/// w{j}          the sibling's word j at ptr + 4j, read and written back at
///               4·cycle + FRAME_DELTA, its gap in [0, 2^38), and a word: its
///               two RANGE16 halfwords
/// receive  (cycle, stamp + s, n_2s, n_2s+1), s < 4     (cycle, stamp + 8, rest, ptr)
/// send     (cycle, stamp + 16 + s, u_2s, u_2s+1), s < 8
///          (cycle, next + 8, rest_next, ptr + 64)
/// ```
///
/// `s_k = w_2k + 2^32·w_2k+1` is the sibling's lane `k`, read mod `p`. Each
/// word is bounded as a load bounds the word it reads, so a sibling may lie
/// in the advice, whose words nothing else bounds: the lane the hash sees is
/// the one a load of its two words sees. `u` is `M_E(n ‖ s)` where the bit is
/// 0, `M_E(s ‖ n)` where it is 1, degree 2.
fn levels() -> Builder {
    let mut b = Builder::new(family::MERKLE_LEVELS);
    let live = b.live;
    let cycle = b.mcol("cycle");
    let stamp = b.mcol("stamp");
    let next = b.mcol("next");
    b.range16("level_range", Expr::from(stamp) * per_level());
    b.gate("next_rule", next - stamp - live * LEVEL);
    let rest = b.mcol("rest");
    let rest_next = b.mcol("rest_next");
    let ptr = b.mcol("ptr");
    let bit = b.bit("bit");
    b.gate("rest_rule", rest - bit - rest_next * 2);
    let read_ts: Vec<PolyAddress> = (0..SIBLING)
        .map(|j| b.mcol(&format!("w{j}_read_ts")))
        .collect();
    let read: Vec<PolyAddress> = (0..SIBLING)
        .map(|j| b.mcol(&format!("w{j}_read_value")))
        .collect();
    let n: Vec<PolyAddress> = (0..8).map(|i| b.mcol(&format!("n{i}"))).collect();
    let u: Vec<PolyAddress> = (0..16).map(|j| b.mcol(&format!("u{j}"))).collect();
    let lane = |k: usize| read[2 * k] + read[2 * k + 1] * T32;
    for (j, uj) in u.iter().enumerate() {
        let mut e = Expr::from(*uj);
        for (k, nk) in n.iter().enumerate() {
            let (left, right) = (external_entry(j, k), external_entry(j, 8 + k));
            let node = Expr::from(*nk);
            e = e - node.clone() * left - lane(k) * right - (lane(k) - node) * bit * (left - right);
        }
        b.gate(&format!("u{j}_rule"), e);
    }
    for j in 0..SIBLING {
        let addr = Part::plus(ptr, 4 * j as u64);
        access(
            &mut b,
            &format!("w{j}"),
            cycle,
            addr,
            read_ts[j],
            read[j],
            read[j],
        );
        // A word, as a load holds the word it reads: an advised word could be
        // any field element, and the hash must see the lane a load of the
        // same two words would.
        b.word(&format!("w{j}"), read[j].into());
    }
    let space = address_space::MERKLE;
    for s in 0..NODE_PAIRS {
        let at = Part::plus(stamp, s as u64);
        let node = tuple(cycle, at, Part::of(n[2 * s]), Part::of(n[2 * s + 1]));
        b.leaf(false, &format!("receive_n{s}"), space, node);
    }
    let control = tuple(
        cycle,
        Part::plus(stamp, CONTROL),
        Part::of(rest),
        Part::of(ptr),
    );
    b.leaf(false, "receive_control", space, control);
    for s in 0..2 * NODE_PAIRS {
        let at = Part::plus(stamp, STRIDE + s as u64);
        let state = tuple(cycle, at, Part::of(u[2 * s]), Part::of(u[2 * s + 1]));
        b.leaf(true, &format!("send_u{s}"), space, state);
    }
    let sibling = Part::plus(ptr, 4 * SIBLING as u64);
    let control = tuple(
        cycle,
        Part::plus(next, CONTROL),
        Part::of(rest_next),
        sibling,
    );
    b.leaf(true, "send_control", space, control);
    b
}

/// `MERKLE_ROOT`'s circuit over `2^trace_vars` rows; at least `2^16`, its
/// `RANGE16` table's, which the registry refuses below.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    frame_row().artifact(trace_vars)
}

/// `MERKLE_ROOT`'s one channel, `RANGE16`.
pub fn channels() -> Vec<ChannelSpec> {
    frame_row().channels()
}

/// `MERKLE_LEVELS`' circuit over `2^trace_vars` rows, likewise.
pub fn levels_artifact(trace_vars: u32) -> CircuitArtifact {
    levels().artifact(trace_vars)
}

/// `MERKLE_LEVELS`' one channel, `RANGE16`.
pub fn levels_channels() -> Vec<ChannelSpec> {
    levels().channels()
}

/// `MERKLE_ROUNDS`' circuit over `2^trace_vars` rows, likewise: its level's
/// bound.
pub fn rounds_artifact(trace_vars: u32) -> CircuitArtifact {
    rounds(Keyed::Level).artifact(trace_vars)
}

/// `MERKLE_ROUNDS`' one channel, `RANGE16`.
pub fn rounds_channels() -> Vec<ChannelSpec> {
    rounds(Keyed::Level).channels()
}
