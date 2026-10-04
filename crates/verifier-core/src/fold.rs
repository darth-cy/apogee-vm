//! The fold's MSM (`docs/spec/recursion.md` §8.3): `Σ_i s_i·P_i` over BN254's
//! G1 on `FQ_OP`, as tapes a guest replays from its image.
//!
//! Pippenger with 8-bit digits — 32 windows of 256 buckets — shaped so that
//! nothing a replay does depends on a value:
//!
//! - **A point** is one static template: held to the curve, its scalar's 32
//!   `DIGIT`s, then one affine bucket addition in each window, the bucket an
//!   indirect operand through that window's digit cell. The 32 additions land
//!   in 32 windows, so they never collide, and share one inversion.
//! - **An inversion** is a host witness: the template reads it from two cells
//!   and asserts it with one `MULEQ`. [`simulate`] runs a template natively
//!   and fills every one, which is how a host lays a guest's witnesses out;
//!   a template's witnesses have cells of their own, so a guest imports them
//!   all before it replays.
//! - **Bucket `b` starts at `(b + 1)·R`** for a fixed point `R`, so no
//!   addition meets infinity and no running sum adds a point to itself; the
//!   finish subtracts what the offsets added, once, at the end.
//! - **The finish** is static too: each window's running sums, batched across
//!   the 32 windows, then Horner over the windows by doubling.
//!
//! A point is two elements, `x` at its cell and `y` four cells on. `FQ_OP`
//! reads an element's four cells under one timestamp, so they are only ever
//! written together: a template's temporaries are elements on one grid of
//! four from `scratch`, where nothing else writes, and a step's are dead once
//! it is done, so the next step reuses them. A constant's two halves are
//! built in `halves`.

use alloc::vec::Vec;

use constants::{fq_op as q, fr_op};
use constraints::fq_op as arith;
use field::Fr;

use pcs_verify::{PairingSide, ENTRY_POINTS};

use crate::tape::{
    infinity_sentinel, run, Cell, CellTranscript, Memory, Op, ShardTape, Tape, ZERO,
};

/// A scalar's digits, and the windows.
pub const WINDOWS: u32 = fr_op::DIGITS as u32;
/// A window's buckets, bucket 0 the digit-0 bucket no sum reads.
pub const BUCKETS: u32 = 1 << fr_op::DIGIT_BITS;
/// A point's cells: `x`, then `y`.
pub const POINT_CELLS: u32 = 2 * q::ELEMENT_CELLS as u32;
/// The most inversions one template takes: the finish's, 508 running steps,
/// 248 doublings, 31 window additions and the correction.
pub const MAX_HOLES: u32 = 1024;
/// The cells a template's step may take of its own.
pub const SCRATCH: u32 = 1 << 13;

/// The offsets' unit `R = k·G`, `k = 2^200 + 0x524543555253494f4e`, an
/// affine point no input is expected to equal: `x`, then `y`, 64-bit limbs.
pub const OFFSET: [[u64; 4]; 2] = [
    [
        0x8d40_67af_63d2_d4d7,
        0x3e0b_c2f1_ad11_ce1d,
        0x7681_9adc_1441_a768,
        0x275e_6195_d225_85fc,
    ],
    [
        0xee1e_7fe4_76bd_aaa7,
        0x133f_9286_a1a3_e036,
        0x30da_a84e_95be_ba8c,
        0x2ee4_d7f8_5324_6781,
    ],
];

/// `−R''`, `R'' = (Σ_w 256^w)·(Σ_{b=1}^{255} b·(b + 1))·R`: what the
/// offsets add to the finish's Horner sum, negated.
pub const CORRECTION: [[u64; 4]; 2] = [
    [
        0xda86_fd00_efe1_4dc0,
        0x0ccd_ed1a_6af8_6599,
        0x1f5c_204d_407f_490a,
        0x04a8_4cf7_2f2e_d20b,
    ],
    [
        0x20c8_6f9a_027f_5c7c,
        0x5348_7366_16d1_1990,
        0x698b_42eb_c7dd_d4c4,
        0x1a96_4299_c18e_8459,
    ],
];

/// One MSM's cells.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    /// Bucket `b` of window `w` at `buckets + 8·(256·w + b)`.
    pub buckets: Cell,
    /// The 32 digit cells.
    pub digits: Cell,
    /// The point being added.
    pub point: Cell,
    /// The scalar being added; its digit chain consumes it to 0.
    pub scalar: Cell,
    /// Four cells nothing writes: the zero element.
    pub zero: Cell,
    /// The elements 1 and 3.
    pub one: Cell,
    pub three: Cell,
    /// The points `R` and `−R''`.
    pub offset: Cell,
    pub correction: Cell,
    /// The 256 offsets, `(b + 1)·R` at `offsets + 8b`.
    pub offsets: Cell,
    /// Window `w`'s running sums, `S_w` at `sums + 16w` and `T_w` eight on.
    pub sums: Cell,
    /// The result.
    pub result: Cell,
    /// A constant's two 128-bit halves, as `FROM128` reads them.
    pub halves: Cell,
    /// A template's inverse witnesses, two cells a hole.
    pub witnesses: Cell,
    /// Where a template's temporaries start: elements, and nothing else.
    pub scratch: Cell,
}

impl Layout {
    /// The cells from `base` up, in field order, and [`SCRATCH`] beyond.
    pub fn at(base: Cell) -> Layout {
        let mut next = base;
        let mut take = |n: u32| {
            let at = next;
            next += n;
            at
        };
        Layout {
            buckets: take(WINDOWS * BUCKETS * POINT_CELLS),
            digits: take(WINDOWS),
            point: take(POINT_CELLS),
            scalar: take(1),
            zero: take(q::ELEMENT_CELLS as u32),
            one: take(q::ELEMENT_CELLS as u32),
            three: take(q::ELEMENT_CELLS as u32),
            offset: take(POINT_CELLS),
            correction: take(POINT_CELLS),
            offsets: take(BUCKETS * POINT_CELLS),
            sums: take(WINDOWS * 2 * POINT_CELLS),
            result: take(POINT_CELLS),
            halves: take(2),
            // Two to spare: the last hole's `FROM128` reads four cells.
            witnesses: take(2 * MAX_HOLES + 2),
            scratch: take(0),
        }
    }

    /// Bucket `b` of window `w`.
    pub fn bucket(&self, w: u32, b: u32) -> Cell {
        self.buckets + POINT_CELLS * (BUCKETS * w + b)
    }

    /// One past the last cell, its scratch included.
    pub fn end(&self) -> Cell {
        self.scratch + SCRATCH
    }
}

/// An element reference: a word, indirect through a digit cell or not.
#[derive(Clone, Copy, Debug)]
pub struct E {
    pub word: Cell,
    pub digit: Option<Cell>,
}

impl E {
    pub fn at(word: Cell) -> E {
        E { word, digit: None }
    }
    /// A point's `y`, four cells on: an indirect word moves with it.
    fn y(self) -> E {
        E {
            word: self.word + q::ELEMENT_CELLS as u32,
            ..self
        }
    }
}

/// One `FQ_OP` call; the indirect operands share the one digit cell.
fn fq(t: &mut Tape, code: u32, d: E, a: E, b: E) {
    let mut digit = ZERO;
    let mut word = code;
    for (operand, flag) in [(d, q::IND_D), (a, q::IND_A), (b, q::IND_B)] {
        if let Some(g) = operand.digit {
            assert!(
                digit == ZERO || digit == g,
                "fold: two digit cells in one op"
            );
            digit = g;
            word |= flag;
        }
    }
    t.ops.push(Op::Fq([
        word | (digit << q::DIGIT_SHIFT),
        d.word,
        a.word,
        b.word,
    ]));
}

/// A fresh element's reference.
fn fresh(t: &mut Tape) -> E {
    E::at(t.fresh(q::ELEMENT_CELLS as u32))
}

/// Where a template needs an inverse: the element at `of`, inverted, goes
/// into `into` and `into + 1` as its two 128-bit halves before op `at` runs.
#[derive(Clone, Copy, Debug)]
pub struct Hole {
    pub at: usize,
    pub of: Cell,
    pub into: Cell,
}

/// A static template and its inverses.
pub struct Template {
    pub ops: Vec<Op>,
    pub holes: Vec<Hole>,
}

/// A template under construction: its tape and its holes.
struct Build {
    t: Tape,
    holes: Vec<Hole>,
    witnesses: Cell,
}

impl Build {
    fn new(l: &Layout) -> Build {
        Build {
            t: Tape::new(l.scratch),
            holes: Vec::new(),
            witnesses: l.witnesses,
        }
    }

    fn done(self) -> Template {
        assert!(
            self.holes.len() as u32 <= MAX_HOLES,
            "fold: more holes than room"
        );
        Template {
            ops: self.t.ops,
            holes: self.holes,
        }
    }

    /// The witness at a hole: `inv` from its two halves, held by one
    /// `MULEQ` to invert `of` — `MULEQ` keeps its `d`, the element 1.
    fn witness(&mut self, of: E, one: E) -> E {
        let into = self.witnesses + 2 * self.holes.len() as u32;
        self.holes.push(Hole {
            at: self.t.ops.len(),
            of: of.word,
            into,
        });
        let inv = fresh(&mut self.t);
        fq(&mut self.t, q::FROM128, inv, E::at(into), one);
        fq(&mut self.t, q::MULEQ, one, inv, of);
        inv
    }

    /// `acc_k ← acc_k + add_k` for every pair, affine, one inversion between
    /// them all. The accumulators are distinct points; the temporaries are
    /// given back once the step is done.
    fn batched_add(&mut self, pairs: &[(E, E)], one: E) {
        let mark = self.t.mark();
        let n = pairs.len();
        let mut delta = Vec::with_capacity(n);
        let mut prefix: Vec<E> = Vec::with_capacity(n);
        for (k, (acc, add)) in pairs.iter().enumerate() {
            let dx = fresh(&mut self.t);
            fq(&mut self.t, q::SUB, dx, *acc, *add);
            delta.push(dx);
            if k == 0 {
                prefix.push(dx);
            } else {
                let p = fresh(&mut self.t);
                fq(&mut self.t, q::MUL, p, prefix[k - 1], dx);
                prefix.push(p);
            }
        }
        let mut inv = self.witness(prefix[n - 1], one);
        let mut inverses = alloc::vec![inv; n];
        for k in (1..n).rev() {
            let own = fresh(&mut self.t);
            fq(&mut self.t, q::MUL, own, inv, prefix[k - 1]);
            inverses[k] = own;
            let next = fresh(&mut self.t);
            fq(&mut self.t, q::MUL, next, inv, delta[k]);
            inv = next;
        }
        inverses[0] = inv;
        for ((acc, add), inv) in pairs.iter().zip(inverses) {
            let t = &mut self.t;
            let (dy, lam, lam2, sx, u, v) =
                (fresh(t), fresh(t), fresh(t), fresh(t), fresh(t), fresh(t));
            fq(t, q::SUB, dy, acc.y(), add.y());
            fq(t, q::MUL, lam, dy, inv);
            fq(t, q::MUL, lam2, lam, lam);
            fq(t, q::ADD, sx, *acc, *add);
            fq(t, q::SUB, *acc, lam2, sx);
            fq(t, q::SUB, u, *add, *acc);
            fq(t, q::MUL, v, lam, u);
            fq(t, q::SUB, acc.y(), v, add.y());
        }
        self.t.reset(mark);
    }

    /// `p ← 2p`, affine, its inversion a hole of its own.
    fn double(&mut self, p: E, l: &Layout) {
        let mark = self.t.mark();
        let t = &mut self.t;
        let (xx, num, den) = (fresh(t), fresh(t), fresh(t));
        fq(t, q::MUL, xx, p, p);
        fq(t, q::MUL, num, xx, E::at(l.three));
        fq(t, q::ADD, den, p.y(), p.y());
        let inv = self.witness(den, E::at(l.one));
        let t = &mut self.t;
        let (lam, lam2, sx, x3, u, v) =
            (fresh(t), fresh(t), fresh(t), fresh(t), fresh(t), fresh(t));
        fq(t, q::MUL, lam, num, inv);
        fq(t, q::MUL, lam2, lam, lam);
        fq(t, q::ADD, sx, p, p);
        fq(t, q::SUB, x3, lam2, sx);
        fq(t, q::SUB, u, p, x3);
        fq(t, q::MUL, v, lam, u);
        fq(t, q::SUB, p.y(), v, p.y());
        fq(t, q::ADD, p, x3, E::at(l.zero));
        self.t.reset(mark);
    }
}

/// `d ← p`, a point's two elements.
fn copy_point(t: &mut Tape, d: E, p: E, zero: E) {
    fq(t, q::ADD, d, p, zero);
    fq(t, q::ADD, d.y(), p.y(), zero);
}

/// An element from a constant's limbs: each 128-bit half built in its
/// `halves` cell a word at a time from the top, then `FROM128`.
fn constant_element(t: &mut Tape, d: E, limbs: &[u64; 4], l: &Layout) {
    for (k, pair) in limbs.chunks(2).enumerate() {
        let cell = l.halves + k as u32;
        let words = [pair[1] >> 32, pair[1], pair[0] >> 32, pair[0]].map(|w| w as u32);
        t.fr(fr_op::IMM, cell, ZERO, words[0]);
        for w in &words[1..] {
            t.fr(fr_op::SHL, cell, cell, *w);
        }
    }
    fq(t, q::FROM128, d, E::at(l.halves), E::at(l.zero));
}

/// A point from its coordinates' limbs.
fn constant_point(t: &mut Tape, at: Cell, point: &[[u64; 4]; 2], l: &Layout) {
    for (c, limbs) in point.iter().enumerate() {
        constant_element(t, E::at(at + c as u32 * q::ELEMENT_CELLS as u32), limbs, l);
    }
}

fn pow64() -> Fr {
    Fr::from_u64(1 << 32) * Fr::from_u64(1 << 32)
}

/// Once an MSM: the constants, the offsets `(b + 1)·R` by a chain — `2R` a
/// doubling, every later one an addition of `R` to a different multiple —
/// and bucket `b` of every window set to `(b + 1)·R`.
pub fn prelude(l: &Layout) -> Template {
    let mut b = Build::new(l);
    let zero = E::at(l.zero);
    constant_element(&mut b.t, E::at(l.one), &[1, 0, 0, 0], l);
    constant_element(&mut b.t, E::at(l.three), &[3, 0, 0, 0], l);
    constant_point(&mut b.t, l.offset, &OFFSET, l);
    constant_point(&mut b.t, l.correction, &CORRECTION, l);
    let offset = |k: u32| E::at(l.offsets + POINT_CELLS * k);
    copy_point(&mut b.t, offset(0), E::at(l.offset), zero);
    copy_point(&mut b.t, offset(1), E::at(l.offset), zero);
    b.double(offset(1), l);
    for k in 2..BUCKETS {
        copy_point(&mut b.t, offset(k), offset(k - 1), zero);
        b.batched_add(&[(offset(k), E::at(l.offset))], E::at(l.one));
    }
    for w in 0..WINDOWS {
        for k in 0..BUCKETS {
            copy_point(&mut b.t, E::at(l.bucket(w, k)), offset(k), zero);
        }
    }
    b.done()
}

/// One point: held to the curve, its scalar's digits, then one bucket
/// addition a window, batched. The caller has put the point at `point` and
/// the scalar at `scalar`.
pub fn point_template(l: &Layout) -> Template {
    let mut b = Build::new(l);
    // `y² ≡ x³ + 3`: BN254's G1 has cofactor 1, so on the curve is in the
    // group. `MULEQ` holds `y²·1` to `x³ + 3`, which it keeps.
    let p = E::at(l.point);
    let t = &mut b.t;
    let (yy, xx, xxx, rhs) = (fresh(t), fresh(t), fresh(t), fresh(t));
    fq(t, q::MUL, yy, p.y(), p.y());
    fq(t, q::MUL, xx, p, p);
    fq(t, q::MUL, xxx, xx, p);
    fq(t, q::ADD, rhs, xxx, E::at(l.three));
    fq(t, q::MULEQ, rhs, yy, E::at(l.one));
    for w in 0..WINDOWS {
        t.fr(fr_op::DIGIT, l.digits + w, l.scalar, l.scalar);
    }
    t.assert_eq(l.scalar, ZERO);
    let pairs: Vec<(E, E)> = (0..WINDOWS)
        .map(|w| {
            (
                E {
                    word: l.bucket(w, 0),
                    digit: Some(l.digits + w),
                },
                E::at(l.point),
            )
        })
        .collect();
    b.batched_add(&pairs, E::at(l.one));
    b.done()
}

/// The finish: each window's `T_w = Σ_b b·B_w[b]` by running sums, batched
/// across the windows; then `Σ_w 256^w·T_w` by Horner, doubling; then `−R''`.
/// The result is at `result`.
pub fn finish_template(l: &Layout) -> Template {
    let mut b = Build::new(l);
    let zero = E::at(l.zero);
    let one = E::at(l.one);
    let s = |w: u32| E::at(l.sums + 2 * POINT_CELLS * w);
    let tt = |w: u32| E::at(l.sums + 2 * POINT_CELLS * w + POINT_CELLS);
    for w in 0..WINDOWS {
        let top = E::at(l.bucket(w, BUCKETS - 1));
        copy_point(&mut b.t, s(w), top, zero);
        copy_point(&mut b.t, tt(w), top, zero);
    }
    for k in (1..BUCKETS - 1).rev() {
        let pairs: Vec<(E, E)> = (0..WINDOWS)
            .map(|w| (s(w), E::at(l.bucket(w, k))))
            .collect();
        b.batched_add(&pairs, one);
        let pairs: Vec<(E, E)> = (0..WINDOWS).map(|w| (tt(w), s(w))).collect();
        b.batched_add(&pairs, one);
    }
    let acc = E::at(l.result);
    copy_point(&mut b.t, acc, tt(WINDOWS - 1), zero);
    for w in (0..WINDOWS - 1).rev() {
        for _ in 0..fr_op::DIGIT_BITS {
            b.double(acc, l);
        }
        b.batched_add(&[(acc, tt(w))], one);
    }
    b.batched_add(&[(acc, E::at(l.correction))], one);
    b.done()
}

/// Run `template` natively, filling every hole with its inverse; returns the
/// inverses in hole order — the words a guest imports — or the op that
/// refused.
pub fn simulate(template: &Template, memory: &mut Memory) -> Result<Vec<[u64; 4]>, usize> {
    let mut witnesses = Vec::with_capacity(template.holes.len());
    let mut from = 0;
    for hole in &template.holes {
        run(&template.ops[from..hole.at], memory, &[]).map_err(|i| from + i)?;
        let mut element = [0u64; 4];
        for (k, limb) in element.iter_mut().enumerate() {
            *limb = arith::limb(memory.get(hole.of + k as u32)).ok_or(hole.at)?;
        }
        let inv = arith::inv_mod_q(element);
        for (k, half) in halves(&inv).into_iter().enumerate() {
            memory.set(hole.into + k as u32, half);
        }
        witnesses.push(inv);
        from = hole.at;
    }
    run(&template.ops[from..], memory, &[]).map_err(|i| from + i)?;
    Ok(witnesses)
}

/// An element's two 128-bit halves, as the cells `FROM128` reads.
pub fn halves(limbs: &[u64; 4]) -> [Fr; 2] {
    [
        Fr::from_u64(limbs[0]) + Fr::from_u64(limbs[1]) * pow64(),
        Fr::from_u64(limbs[2]) + Fr::from_u64(limbs[3]) * pow64(),
    ]
}

// ---------------------------------------------------------------------------
// A node's fold
// ---------------------------------------------------------------------------

/// Which of the accumulator's two MSMs a point goes to: `A`, paired with
/// `[1]_2`, or `B`, with `[x]_2` (`docs/spec/accumulator.md` §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    A,
    B,
}

/// One point a shard owes the accumulator: its four transcript limbs'
/// cells — `x` low, `x` high, `y` low, `y` high, consecutive — its scalar's
/// cell, and its side.
#[derive(Clone, Copy, Debug)]
pub struct FoldPoint {
    pub limbs: Cell,
    pub scalar: Cell,
    pub side: Side,
}

/// A node's cells beside its shards' tapes: its own transcript's state, two
/// constants, the shard being folded's scalars and a fold tape's scratch —
/// field cells all, so a `FROM128` reading past a shard's last limbs reads
/// one of them — and then the two MSMs.
#[derive(Clone, Copy, Debug)]
pub struct Node {
    /// The node transcript's state, three cells, carried from shard to shard.
    pub state: Cell,
    /// `[1]_1`'s four transcript limbs.
    pub generator: Cell,
    /// `G1_INFINITY_SENTINEL`.
    pub sentinel: Cell,
    /// The shard being folded's point scalars, one cell a point.
    pub scalars: Cell,
    /// Where a fold tape's own cells start.
    pub scratch: Cell,
    pub a: Layout,
    pub b: Layout,
}

impl Node {
    /// The cells from `base` up, room for `points` scalars a shard.
    pub fn at(base: Cell, points: u32) -> Node {
        let scratch = base + 8 + points;
        let a = Layout::at(scratch + SCRATCH);
        Node {
            state: base,
            generator: base + 3,
            sentinel: base + 7,
            scalars: base + 8,
            scratch,
            a,
            b: Layout::at(a.end()),
        }
    }

    /// One past the node's last cell.
    pub fn end(&self) -> Cell {
        self.b.end()
    }

    /// The layout `side` adds into.
    pub fn layout(&self, side: Side) -> &Layout {
        match side {
            Side::A => &self.a,
            Side::B => &self.b,
        }
    }

    /// The node's constants: `[1]_1`'s limbs and the sentinel, as cells.
    pub fn prelude(&self) -> Vec<Op> {
        let mut t = Tape::new(self.scratch);
        // BN254's G1 generator, `(1, 2)`, the SRS's `[1]_1`.
        for (k, v) in [1u64, 0, 2, 0].into_iter().enumerate() {
            let c = t.constant(Fr::from_u64(v));
            t.fr(fr_op::ADD, self.generator + k as u32, c, ZERO);
        }
        let s = t.constant(infinity_sentinel());
        t.fr(fr_op::ADD, self.sentinel, s, ZERO);
        t.ops
    }
}

/// After a shard's tape: the node transcript absorbs the shard's final state
/// and draws `w` and `w′`, and every point the shard owes gets its scalar —
/// entry `i` of its Mercury check `w·e_i` on the side `ENTRY_POINTS` gives
/// it, `cm*`'s `w′` more, and each opened commitment `−w′·ρ^i`: the batch
/// check `cm* − Σ ρ^i·cm_i` folded beside the Mercury check. Returns the
/// tape and the points, in the order a guest adds them.
pub fn shard_fold(shape: &ShardTape, node: &Node) -> (Vec<Op>, Vec<FoldPoint>) {
    use constants::transcript_tags as tags;
    let mut t = Tape::new(node.scratch);
    let out = &shape.outputs;
    let mut tr = CellTranscript::at(node.state);
    let state = [out.state, out.state + 1, out.state + 2];
    tr.append(&mut t, tags::FOLD_STATE, &state);
    let w = tr.challenge(&mut t, tags::FOLD_WEIGHT);
    let w2 = tr.challenge(&mut t, tags::FOLD_WEIGHT);
    for k in 0..3 {
        t.fr(fr_op::ADD, node.state + k, tr.state() + k, ZERO);
    }

    let e = &out.mercury;
    let mut points: Vec<FoldPoint> = Vec::new();
    let mut add = |t: &mut Tape, limbs: Cell, side: Side, scalar: &dyn Fn(&mut Tape, Cell)| {
        let cell = node.scalars + points.len() as u32;
        scalar(t, cell);
        points.push(FoldPoint {
            limbs,
            scalar: cell,
            side,
        });
    };
    // `[cm*, the proof's eight points, [1]_1]`, as `ENTRY_POINTS` indexes them.
    let limbs = |k: usize| match k {
        0 => out.cm_star[0],
        9 => node.generator,
        k => out.points[k - 1][0],
    };
    for (i, (side, k)) in ENTRY_POINTS.iter().enumerate() {
        let side = match side {
            PairingSide::G2One => Side::A,
            PairingSide::G2X => Side::B,
        };
        add(&mut t, limbs(*k), side, &|t, c| {
            t.fr(fr_op::MUL, c, w, e[i]);
            if i == 0 {
                t.fr(fr_op::ADD, c, c, w2);
            }
        });
    }
    for (cm, rho) in out.commitments.iter().zip(&out.batch) {
        add(&mut t, cm[0], Side::A, &|t, c| {
            t.fr(fr_op::MUL, c, w2, *rho);
            t.fr(fr_op::SUB, c, ZERO, c);
        });
    }
    (t.ops, points)
}

/// The ops that put a point and its scalar where a template reads them:
/// its two coordinates from their limbs by `FROM128`, its scalar copied —
/// or, for the point at infinity, the four `EQ`s that hold its limbs to the
/// sentinel and nothing else, since it adds nothing.
pub fn load_point(p: &FoldPoint, l: &Layout, sentinel: Cell, infinity: bool) -> Vec<Op> {
    if infinity {
        return (0..4)
            .map(|k| Op::Fr([fr_op::EQ, 0, p.limbs + k, sentinel]))
            .collect();
    }
    alloc::vec![
        Op::Fq([q::FROM128, l.point, p.limbs, l.zero]),
        Op::Fq([q::FROM128, l.point + 4, p.limbs + 2, l.zero]),
        Op::Fr([fr_op::ADD, l.scalar, p.scalar, ZERO]),
    ]
}
