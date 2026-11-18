//! The `MPT_ROOT` precompile: a crit-bit trie's root from the op program the
//! SDK emits over its pruned trie (`constants::delegation::mpt`), as three
//! circuits on `crate::delegation`'s builder.
//!
//! - `MPT`, one row a call: the frame's 18 words, op 0's state sent, `cur`
//!   zero and the control `(OPS, 0)`, op `n`'s received, its raw lanes and the
//!   control `(OPS + 8n, pending)`, and the root written canonical, lane 0
//!   with `pending` added.
//! - `MPT_NODES`, one row an op: its state and its control received, its info
//!   and arg read from RAM and its info decoded, its block read where it has
//!   one, a JOIN's parked value received and a park sent, and op `i + 1`'s
//!   control sent: for a LOAD the block's lanes as op `i + 1`'s state, for a
//!   hash op its two children in order through `M_E` as boundary 1.
//! - `MPT_ROUNDS`, sixteen rows a hash op: `POSEIDON2_ROUNDS`' rows
//!   (`crate::poseidon2::rounds`) from boundary 1 to 16, the last writing
//!   only the first eight lanes, op `i + 1`'s raw state.
//!
//! The call at `cycle` keeps its state in `address_space::MPT`: op `i` owns
//! the timestamps `256i + 16b + slot`, its boundary 16 op `i + 1`'s boundary
//! 0, and a tuple is `(MPT, cycle, ts, x, y)`. At boundary 0 lane pair `s` of
//! the raw value entering the op is slot `s`, the control `(op_ptr, pending)`
//! slot 8 and a park's pair `s` slot `12 + s`; at boundaries 1 to 16 pair `s`
//! of a permutation state is slot `s`. Every row's stamp is bounded below
//! `2^20` ops, so a timestamp is one op and one slot.

use alloc::format;
use alloc::vec::Vec;

use constants::delegation::mpt::{
    BLOCK, COUNT, DEPTH_BOUND, DEPTH_SHIFT, FRAME, LEFT, MAX_OPS, OPS, OP_WORDS, PARK, ROOT,
};
use constants::delegation::Per;
use constants::{address_space, delegation, ecall, family};
use field::Fp;

use crate::delegation::{access, access_under, frame, Builder, Part};
use crate::family::{Expr, T32};
use crate::lookup::ChannelSpec;
use crate::poseidon2::{canonical, external_entry, rounds, Keyed, ROWS};
use crate::{CircuitArtifact, PolyAddress};

/// Timestamps a boundary takes: its eight lane pairs, the control at
/// [`CONTROL`] and a park at [`PARKED`].
pub const STRIDE: u64 = 16;
/// The control's slot in an op's boundary 0.
pub const CONTROL: u64 = 8;
/// A park's first slot in an op's boundary 0.
pub const PARKED: u64 = 12;
/// Timestamps an op takes: sixteen boundaries, its node row's and its fifteen
/// rounds'.
pub const SPAN: u64 = 16 * STRIDE;
/// Lane pairs a value is, a digest's eight lanes.
pub const NODE_PAIRS: usize = 4;
/// Bits of an op's index: a call's ops number at most `2^20`.
pub const OP_BITS: u32 = MAX_OPS.trailing_zeros();
/// Bits of an info word's depth.
pub const DEPTH_BITS: u32 = DEPTH_BOUND.trailing_zeros();

const _: () = {
    assert!(MAX_OPS == 1 << OP_BITS && DEPTH_BOUND == 1 << DEPTH_BITS);
    // A park's pairs and the control fit boundary 0 beside the lane pairs.
    assert!(NODE_PAIRS as u64 <= CONTROL && CONTROL < PARKED);
    assert!(PARKED + NODE_PAIRS as u64 <= STRIDE && 2 * NODE_PAIRS as u64 <= STRIDE);
    // The info word: a kind below 4, then park, left and the depth.
    assert!(delegation::mpt::JOIN < PARK && 2 * PARK == LEFT && 2 * LEFT == 1 << DEPTH_SHIFT);
    // An op is its two words and its block, a digest's 8 lanes.
    assert!(BLOCK == 4 * NODE_PAIRS && OP_WORDS == delegation::mpt::OP + BLOCK);
    assert!(FRAME == ROOT + BLOCK && OPS < ROOT && COUNT < ROOT);
    // The registry's words an entry and rows an entry.
    let t = &delegation::TYPES;
    assert!(t[8].0 == family::MPT && t[8].1 == ecall::MPT_ROOT);
    assert!(t[8].2 == FRAME && t[8].3 == 1 && matches!(t[8].4, Per::Call));
    assert!(t[9].0 == family::MPT_NODES && t[9].1 == ecall::MPT_ROOT);
    assert!(t[9].2 == OP_WORDS && t[9].3 == 1 && matches!(t[9].4, Per::Op));
    assert!(t[10].0 == family::MPT_ROUNDS && t[10].1 == ecall::MPT_ROOT);
    assert!(t[10].2 == OP_WORDS && t[10].3 as usize == ROWS && matches!(t[10].4, Per::Hash));
};

/// `1/SPAN`: what takes a stamp's `256i` to its op, bounded.
pub fn per_op() -> Fp {
    Fp::from_u64(SPAN).inverse().expect("256 is a unit")
}

/// A state tuple of the call at `cycle`: `(MPT, cycle, at, x, y)`.
fn tuple(cycle: PolyAddress, at: Part, x: Part, y: Part) -> [Part; 4] {
    [Part::of(cycle), at, x, y]
}

/// A new `M` column held boolean by `<name>_boolean`: a leaf's mask.
fn mask(b: &mut Builder, name: &str) -> PolyAddress {
    let x = b.mcol(name);
    b.gate(&format!("{name}_boolean"), x - x * x);
    x
}

/// `MPT`: the frame, the op count in range, op 0's state sent and op `n`'s
/// received, the root written canonical.
///
/// ```text
/// count       count − live < 2^20               1 ≤ n ≤ 2^20
/// last_rule   last − 256·count                  op n's stamp
/// end_rule    end − ops − 8·count               op n's op pointer
/// root{l}     canonical(o_l + [l = 0]·pending; write_{2 + 2l}, write_{3 + 2l})
/// send     (cycle, s, 0, 0), s < 4              (cycle, 8, ops, 0)
/// receive  (cycle, last + s, o_2s, o_2s+1)      (cycle, last + 8, end, pending)
/// ```
fn frame_row() -> Builder {
    let mut b = Builder::new(family::MPT);
    let live = b.live;
    let f = frame(&mut b, ecall::MPT_ROOT, FRAME, |j| j >= ROOT);
    let (ops, count) = (f.words[OPS].read, f.words[COUNT].read);
    b.bounded("count", count - live, OP_BITS);
    let last = b.mcol("last");
    b.gate("last_rule", last - count * SPAN);
    let end = b.mcol("end");
    b.gate(
        "end_rule",
        end - ops - count * (4 * delegation::mpt::OP as u64),
    );
    let o: Vec<PolyAddress> = (0..8).map(|l| b.mcol(&format!("o{l}"))).collect();
    let pending = b.mcol("pending");
    for (l, ol) in o.iter().enumerate() {
        let lane = match l {
            0 => *ol + pending,
            _ => Expr::from(*ol),
        };
        let (lo, hi) = (f.words[ROOT + 2 * l].write, f.words[ROOT + 2 * l + 1].write);
        canonical(&mut b, &format!("root{l}"), lane, lo, hi);
    }
    let space = address_space::MPT;
    for s in 0..NODE_PAIRS {
        let at = s as u64;
        let zero = tuple(
            f.cycle,
            Part::constant(at),
            Part::default(),
            Part::default(),
        );
        b.leaf(true, &format!("send_cur{s}"), space, zero);
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
        Part::of(ops),
        Part::default(),
    );
    b.leaf(true, "send_control", space, start);
    let spent = tuple(
        f.cycle,
        Part::plus(last, CONTROL),
        Part::of(end),
        Part::of(pending),
    );
    b.leaf(false, "receive_control", space, spent);
    b
}

/// `MPT_NODES`: op `i` of the call at `cycle`, its stamp `256i`.
///
/// ```text
/// masks         is_hash is_join park is_load block: M bits, zero off a live row
/// is_load_rule  is_load − live + is_hash        block_rule   block − live + is_join
/// join_rule     is_join − is_join·is_hash       park_rule    park − park·live
/// info_rule     info − (is_hash − is_join) − 2·is_join − 4·park − 8·left − 16·d
///               left a bit, d < 2^9
/// pending_rule  pending_next − is_hash·(d + 1)
/// other{k}_rule block·(other_k − w_2k − 2^32·w_2k+1)              k < 8
/// u{j}_rule     u_j − Σ_k M_E[j][k]·L_k − M_E[j][8 + k]·R_k        j < 16
///               cur_k = o_k + [k = 0]·pending, L_k = cur_k + left·(other_k − cur_k),
///               R_k = other_k + left·(cur_k − other_k)
/// op            stamp/256 < 2^20
/// park_at_rule  park_at − 256·is_join·arg
/// join          (stamp − park_at)/256 − is_join < 2^20: i − 1 − arg on a JOIN, i elsewhere
/// info, arg     the words at op_ptr and op_ptr + 4, read and written back at
///               4·cycle + FRAME_DELTA, their gaps in [0, 2^38)
/// w{j}          the block's word j at arg + 4j likewise under block, and a word:
///               its two RANGE16 halfwords
/// receive  (cycle, stamp + s, o_2s, o_2s+1), s < 4    (cycle, stamp + 8, op_ptr, pending)
///          under is_join (cycle, park_at + 12 + s, other_2s, other_2s+1)
/// send     (cycle, stamp + 264, op_ptr + 8, pending_next)
///          under is_load (cycle, stamp + 256 + s, other_2s, other_2s+1)
///          under is_hash (cycle, stamp + 16 + s, u_2s, u_2s+1), s < 8
///          under park    (cycle, stamp + 12 + s, cur_2s, cur_2s+1)
/// ```
///
/// The kind is `is_hash + is_join`: a LOAD 0, a SIB 1, a JOIN 2, and no
/// info word with kind 3 or at or above `2^13` decodes. A block's lane `k` is
/// `w_2k + 2^32·w_2k+1`, read mod `p`; each word is bounded as a load bounds
/// the word it reads, as an advised block's words are otherwise unbounded.
/// `u` is `M_E(cur ‖ other)` where `left` is 0 and `M_E(other ‖ cur)` where it
/// is 1, degree 2. A JOIN's arg is the index of an op before it, `join`
/// holding `i − 1 − arg` below `2^20`, as the executor holds it: without the
/// bound a JOIN could take its own park, or a later op's. An arg the bound
/// leaves within `2^20` of `p` reads a stamp no op sends. For a LOAD or a SIB
/// the arg is the block's address, which an access at it holds to a word.
fn nodes() -> Builder {
    let mut b = Builder::new(family::MPT_NODES);
    let live = b.live;
    let cycle = b.mcol("cycle");
    let stamp = b.mcol("stamp");
    let op_ptr = b.mcol("op_ptr");
    let pending = b.mcol("pending");
    let pending_next = b.mcol("pending_next");
    let is_hash = mask(&mut b, "is_hash");
    let is_join = mask(&mut b, "is_join");
    let park = mask(&mut b, "park");
    let is_load = mask(&mut b, "is_load");
    let block = mask(&mut b, "block");
    b.gate("is_load_rule", is_load - live + is_hash);
    b.gate("block_rule", block - live + is_join);
    b.gate("join_rule", is_join - is_join * is_hash);
    b.gate("park_rule", park - park * live);
    let [info_ts, info, arg_ts, arg] = [
        "info_read_ts",
        "info_read_value",
        "arg_read_ts",
        "arg_read_value",
    ]
    .map(|n| b.mcol(n));
    let read_ts: Vec<PolyAddress> = (0..BLOCK)
        .map(|j| b.mcol(&format!("w{j}_read_ts")))
        .collect();
    let read: Vec<PolyAddress> = (0..BLOCK)
        .map(|j| b.mcol(&format!("w{j}_read_value")))
        .collect();
    let o: Vec<PolyAddress> = (0..8).map(|k| b.mcol(&format!("o{k}"))).collect();
    let other: Vec<PolyAddress> = (0..8).map(|k| b.mcol(&format!("other{k}"))).collect();
    let u: Vec<PolyAddress> = (0..16).map(|j| b.mcol(&format!("u{j}"))).collect();
    let park_at = b.mcol("park_at");

    let left = b.bit("left");
    let d = b.col("d");
    b.small("d", d, DEPTH_BITS);
    // LOAD 0, SIB 1, JOIN 2.
    let kind = (is_hash - is_join) + is_join * 2;
    b.gate(
        "info_rule",
        info - kind - park * PARK as u64 - left * LEFT as u64 - d * (1u64 << DEPTH_SHIFT),
    );
    b.gate(
        "pending_rule",
        pending_next - is_hash * (d + crate::family::k(1)),
    );
    let lane = |k: usize| read[2 * k] + read[2 * k + 1] * T32;
    for (k, x) in other.iter().enumerate() {
        b.gate(&format!("other{k}_rule"), (*x - lane(k)) * block);
    }
    let cur = |k: usize| match k {
        0 => o[0] + pending,
        _ => Expr::from(o[k]),
    };
    for (j, uj) in u.iter().enumerate() {
        let mut e = Expr::from(*uj);
        for (k, x) in other.iter().enumerate() {
            let (l, r) = (external_entry(j, k), external_entry(j, 8 + k));
            let swap = (*x - cur(k)) * left;
            e = e - cur(k) * l - Expr::from(*x) * r - swap * (l - r);
        }
        b.gate(&format!("u{j}_rule"), e);
    }
    b.bounded("op", Expr::from(stamp) * per_op(), OP_BITS);
    b.gate("park_at_rule", park_at - is_join * arg * SPAN);

    access(&mut b, "info", cycle, Part::of(op_ptr), info_ts, info, info);
    access(
        &mut b,
        "arg",
        cycle,
        Part::plus(op_ptr, 4),
        arg_ts,
        arg,
        arg,
    );
    for j in 0..BLOCK {
        let addr = Part::plus(arg, 4 * j as u64);
        let name = format!("w{j}");
        access_under(
            &mut b, block, &name, cycle, addr, read_ts[j], read[j], read[j],
        );
        // A word, as a load holds the word it reads: an advised word could be
        // any field element, and the hash must see the lane a load of the
        // same two words would.
        b.word(&name, read[j].into());
    }
    b.bounded(
        "join",
        (stamp - Expr::from(park_at)) * per_op() - Expr::from(is_join),
        OP_BITS,
    );

    let space = address_space::MPT;
    let pair = |v: &[PolyAddress], s: usize| (Part::of(v[2 * s]), Part::of(v[2 * s + 1]));
    for s in 0..NODE_PAIRS {
        let (x, y) = pair(&o, s);
        let state = tuple(cycle, Part::plus(stamp, s as u64), x, y);
        b.leaf(false, &format!("receive_o{s}"), space, state);
    }
    let control = tuple(
        cycle,
        Part::plus(stamp, CONTROL),
        Part::of(op_ptr),
        Part::of(pending),
    );
    b.leaf(false, "receive_control", space, control);
    for s in 0..NODE_PAIRS {
        let (x, y) = pair(&other, s);
        let parked = tuple(cycle, Part::plus(park_at, PARKED + s as u64), x, y);
        b.leaf_under(is_join, false, &format!("receive_parked{s}"), space, parked);
    }
    let next = tuple(
        cycle,
        Part::plus(stamp, SPAN + CONTROL),
        Part::plus(op_ptr, 4 * delegation::mpt::OP as u64),
        Part::of(pending_next),
    );
    b.leaf(true, "send_control", space, next);
    for s in 0..NODE_PAIRS {
        let (x, y) = pair(&other, s);
        let state = tuple(cycle, Part::plus(stamp, SPAN + s as u64), x, y);
        b.leaf_under(is_load, true, &format!("send_load{s}"), space, state);
    }
    for s in 0..2 * NODE_PAIRS {
        let (x, y) = pair(&u, s);
        let state = tuple(cycle, Part::plus(stamp, STRIDE + s as u64), x, y);
        b.leaf_under(is_hash, true, &format!("send_u{s}"), space, state);
    }
    for s in 0..NODE_PAIRS {
        let x = match s {
            0 => Part {
                columns: alloc::vec![o[0], pending],
                plus: 0,
            },
            _ => Part::of(o[2 * s]),
        };
        let parked = tuple(
            cycle,
            Part::plus(stamp, PARKED + s as u64),
            x,
            Part::of(o[2 * s + 1]),
        );
        b.leaf_under(park, true, &format!("send_park{s}"), space, parked);
    }
    b
}

/// `MPT`'s circuit over `2^trace_vars` rows; at least `2^16`, its `RANGE16`
/// table's, which the registry refuses below.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    frame_row().artifact(trace_vars)
}

/// `MPT`'s one channel, `RANGE16`.
pub fn channels() -> Vec<ChannelSpec> {
    frame_row().channels()
}

/// `MPT_NODES`' circuit over `2^trace_vars` rows, likewise.
pub fn nodes_artifact(trace_vars: u32) -> CircuitArtifact {
    nodes().artifact(trace_vars)
}

/// `MPT_NODES`' one channel, `RANGE16`.
pub fn nodes_channels() -> Vec<ChannelSpec> {
    nodes().channels()
}

/// `MPT_ROUNDS`' circuit over `2^trace_vars` rows, likewise: its op's bound.
pub fn rounds_artifact(trace_vars: u32) -> CircuitArtifact {
    rounds(Keyed::Op).artifact(trace_vars)
}

/// `MPT_ROUNDS`' one channel, `RANGE16`.
pub fn rounds_channels() -> Vec<ChannelSpec> {
    rounds(Keyed::Op).channels()
}

#[cfg(test)]
mod tests {
    use super::*;
    use constants::lookup_channel::RANGE16;
    use constants::memory::TS_BITS;

    /// `RANGE16`'s obligations an op's bound takes: a chunk, its scaled
    /// bound, and the rest.
    const BOUND_20: usize = 3;
    /// An access's gap, `[0, 2^38)`: two chunks, the top one's scaled bound,
    /// and the rest.
    const GAP: usize = 4;

    /// The budgets, counted: at most `MAX_COMMITTED` committed columns, and
    /// `RANGE16`'s obligations under the 128-leaf tree, its table's fraction
    /// beside them. `MPT`: each frame word's gap, `room`, the count and each
    /// root lane's two words and its canonical bound, 117 with 10 to spare.
    /// `MPT_NODES`: the info's and the arg's gaps, each block word's gap and
    /// its two halfwords, the depth's two, and the op's and the JOIN's
    /// bounds, 112 with 15 to spare. `MPT_ROUNDS`: the op's bound, 3.
    #[test]
    fn mpt_keeps_its_budgets() {
        assert_eq!(TS_BITS, 38, "a gap is two chunks and a 6-bit top");
        let cases = [
            (
                artifact(16),
                FRAME * GAP + 2 + BOUND_20 + 8 * (2 + 2 + 1),
                117,
            ),
            (
                nodes_artifact(16),
                2 * GAP + BLOCK * (GAP + 2) + 2 + 2 * BOUND_20,
                112,
            ),
            (rounds_artifact(16), BOUND_20, 3),
        ];
        for (a, want, count) in cases {
            let committed = a.memory.len() + a.witness.len() + a.setup.len();
            assert!(
                committed <= crate::delegation::MAX_COMMITTED,
                "{committed} committed"
            );
            let obligations = a.lookups.iter().filter(|l| l.channel == RANGE16).count();
            assert_eq!((obligations, want), (count, count));
            assert!(obligations < 128, "{obligations}: past the 128-leaf tree");
        }
    }
}
