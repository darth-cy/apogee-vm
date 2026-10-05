//! The fold's MSM (`docs/spec/recursion.md` §8.3): `Σ_i s_i·P_i` over BN254's
//! G1 on `FQ_OP`, as tapes a guest replays from its image.
//!
//! Pippenger with 8-bit digits over GLV halves — 16 windows of 256 buckets —
//! shaped so that nothing a replay does depends on a value:
//!
//! - **A scalar is split** by BN254's endomorphism `φ(x, y) = (β·x, y) = λ·P`:
//!   `k ≡ s₁·k₁ + λ·s₂·k₂` with `k₁, k₂ < 2^128` and signs `s_i = ±1`, a host
//!   witness ([`split`]) the template holds to `k`. So `k·P` is
//!   `k₁·(s₁P) + k₂·(s₂φ(P))`, two 128-bit scalars over 16 windows, and the
//!   fixed work — which is per window — is half a 256-bit scalar's.
//! - **A point** is one static template: held to the curve, its split held to
//!   its scalar, each half's 16 `DIGIT`s, then one affine bucket addition in
//!   each window for `s₁P` and one for `s₂φ(P)`, the bucket an indirect
//!   operand through that window's digit cell. Each half's 16 additions land
//!   in 16 windows, so they never collide, and share one inversion.
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
//! - **A loop is one template replayed** ([`Phase`]): the running sums are 254
//!   replays of one step whose bucket is indirect through a counter cell the
//!   step itself moves, and so are the offsets, the buckets' setting and the
//!   Horner steps. An MSM's fixed work is some 200k operations a side and its
//!   templates about two thousand.
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

/// A half's digits, and the windows.
pub const WINDOWS: u32 = fr_op::DIGITS as u32 / 2;
/// A window's buckets, bucket 0 the digit-0 bucket no sum reads.
pub const BUCKETS: u32 = 1 << fr_op::DIGIT_BITS;
/// A point's cells: `x`, then `y`.
pub const POINT_CELLS: u32 = 2 * q::ELEMENT_CELLS as u32;
/// The most inversions one template takes: a Horner step's eight doublings
/// and one addition.
pub const MAX_HOLES: u32 = 16;
/// The cells a template's step may take of its own: a batched addition over
/// the 16 windows takes 158 elements.
pub const SCRATCH: u32 = 1 << 11;

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
        0x4dc9_3483_b95a_3212,
        0xfdc5_7bd7_4f56_fcfa,
        0xe0c4_38e4_09bf_cd5a,
        0x1915_6aa8_b205_5643,
    ],
    [
        0xb16b_1b6e_51e4_6536,
        0xff38_a8d2_7df2_3fd2,
        0xe68f_51b6_fb31_820d,
        0x2078_17bb_842c_3511,
    ],
];

/// `β`, the cube root of unity in `Fq` with `(β·x, y) = λ·(x, y)` on G1.
pub const BETA: [u64; 4] = [
    0x5763_4731_77ff_fffe,
    0xd4f2_63f1_acdb_5c4f,
    0x59e2_6bce_a0d4_8bac,
    0,
];

/// `λ`, the cube root of unity in `Fr` that `β` acts as.
pub const LAMBDA: &str = "0x0000000000000000b3c4d79d41a917585bfc41088d8daaa78b17ea66b99c90dd";

/// The short basis of `{(a, b) : a + λ·b ≡ 0 mod r}` [`split`] rounds
/// against, `(a₁, b₁)` then `(a₂, b₂)`, magnitudes and whether each is
/// negative; and `round(2^256·b₂/r)` and `round(−2^256·b₁/r)`, as limbs.
const BASIS: [(u128, bool); 4] = [
    (0x89d3_2568_94d2_13e3, false),
    (0x6f4d_8248_eeb8_59fc_8211_bbeb_7d4f_1128, true),
    (0x6f4d_8248_eeb8_59fd_0be4_e154_1221_250b, false),
    (0x89d3_2568_94d2_13e3, false),
];
const ROUND: [[u64; 3]; 2] = [
    [0xd91d_232e_c7e0_b3d7, 0x2, 0],
    [0x7a7b_d9d4_391e_b18e, 0x4cce_f014_a773_d2cf, 0x2],
];

/// One MSM's cells.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    /// Bucket `b` of window `w` at `buckets + 8·(256·w + b)`.
    pub buckets: Cell,
    /// The 32 digit cells, `k₁`'s then `k₂`'s.
    pub digits: Cell,
    /// The point being added, as loaded and then as `s₁P`; and `s₂φ(P)`.
    pub point: Cell,
    pub point2: Cell,
    /// The scalar being added; its digit chain consumes it to 0.
    pub scalar: Cell,
    /// Four cells nothing writes: the zero element.
    pub zero: Cell,
    /// The elements 1, 3 and `β`.
    pub one: Cell,
    pub three: Cell,
    pub beta: Cell,
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
    /// A loop's counter, an indirect operand's digit, and the field cells
    /// 1, 2 and 256 it steps by.
    pub counter: Cell,
    pub steps: Cell,
    /// `λ`, and two field cells a point's template works in.
    pub lambda: Cell,
    pub work: Cell,
    /// A point's split, `[k₁, k₂, b₁, 0, b₂, 0]`, `b_i` the sign bits and
    /// each followed by a zero so `FROM128` reads it whole; the inverse
    /// witnesses follow it, so a point's witnesses are one run of cells.
    pub split: Cell,
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
            digits: take(2 * WINDOWS),
            point: take(POINT_CELLS),
            point2: take(POINT_CELLS),
            scalar: take(1),
            zero: take(q::ELEMENT_CELLS as u32),
            one: take(q::ELEMENT_CELLS as u32),
            three: take(q::ELEMENT_CELLS as u32),
            beta: take(q::ELEMENT_CELLS as u32),
            offset: take(POINT_CELLS),
            correction: take(POINT_CELLS),
            offsets: take(BUCKETS * POINT_CELLS),
            sums: take(WINDOWS * 2 * POINT_CELLS),
            result: take(POINT_CELLS),
            halves: take(2),
            counter: take(1),
            steps: take(3),
            lambda: take(1),
            work: take(2),
            split: take(6),
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

/// A template and how many times in a row it is replayed: a loop, whose
/// counter the template moves itself.
pub type Phase = (Template, u32);

/// Move the counter by `steps[k]`, `op` being `ADD` or `SUB`.
fn step(t: &mut Tape, l: &Layout, k: u32, op: u32) {
    t.fr(op, l.counter, l.counter, l.steps + k);
}

/// The element at `word + 8·counter`.
fn at_counter(l: &Layout, word: Cell) -> E {
    E {
        word,
        digit: Some(l.counter),
    }
}

/// Once an MSM, before its points: the constants and `2R`; then the offsets
/// `(b + 1)·R`, each `R` more than the last, `b` the counter; then each
/// window's buckets set to the offsets, the counter `256·w`.
pub fn prelude(l: &Layout) -> Vec<Phase> {
    let zero = E::at(l.zero);
    let one = E::at(l.one);
    let offset = |k: u32| E::at(l.offsets + POINT_CELLS * k);

    let mut b = Build::new(l);
    constant_element(&mut b.t, one, &[1, 0, 0, 0], l);
    constant_element(&mut b.t, E::at(l.three), &[3, 0, 0, 0], l);
    constant_element(&mut b.t, E::at(l.beta), &BETA, l);
    let lambda = Fr::from_hex(LAMBDA)
        .expect("λ is a canonical literal")
        .to_bytes();
    let word = |k: usize| u32::from_le_bytes(lambda[4 * k..4 * k + 4].try_into().expect("4"));
    b.t.fr(fr_op::IMM, l.lambda, ZERO, word(7));
    for k in (0..7).rev() {
        b.t.fr(fr_op::SHL, l.lambda, l.lambda, word(k));
    }
    constant_point(&mut b.t, l.offset, &OFFSET, l);
    constant_point(&mut b.t, l.correction, &CORRECTION, l);
    for (k, v) in [1, 2, BUCKETS].into_iter().enumerate() {
        b.t.fr(fr_op::IMM, l.steps + k as u32, ZERO, v);
    }
    copy_point(&mut b.t, offset(0), E::at(l.offset), zero);
    copy_point(&mut b.t, offset(1), E::at(l.offset), zero);
    b.double(offset(1), l);
    b.t.fr(fr_op::IMM, l.counter, ZERO, 2);
    let constants = b.done();

    let mut b = Build::new(l);
    let this = at_counter(l, l.offsets);
    copy_point(&mut b.t, this, at_counter(l, l.offsets - POINT_CELLS), zero);
    b.batched_add(&[(this, E::at(l.offset))], one);
    step(&mut b.t, l, 0, fr_op::ADD);
    let offsets = b.done();

    let mut b = Build::new(l);
    b.t.fr(fr_op::IMM, l.counter, ZERO, 0);
    let reset = b.done();

    let mut b = Build::new(l);
    for k in 0..BUCKETS {
        copy_point(&mut b.t, at_counter(l, l.bucket(0, k)), offset(k), zero);
    }
    step(&mut b.t, l, 2, fr_op::ADD);
    let windows = b.done();

    alloc::vec![
        (constants, 1),
        (offsets, BUCKETS - 2),
        (reset, 1),
        (windows, WINDOWS)
    ]
}

/// One point: held to the curve; its split held to its scalar, each half
/// below `2^128` by its 16 digits and each sign bit a bit; `s₂φ(P)` and
/// `s₁P`; then one bucket addition a window for each, batched. The caller has
/// put the point at `point`, the scalar at `scalar` and its [`split`] at
/// `split`.
pub fn point_template(l: &Layout) -> Template {
    let mut b = Build::new(l);
    // `y² ≡ x³ + 3`: BN254's G1 has cofactor 1, so on the curve is in the
    // group, where `φ` is `λ`. `MULEQ` holds `y²·1` to `x³ + 3`, which it keeps.
    let p = E::at(l.point);
    let t = &mut b.t;
    let (yy, xx, xxx, rhs) = (fresh(t), fresh(t), fresh(t), fresh(t));
    fq(t, q::MUL, yy, p.y(), p.y());
    fq(t, q::MUL, xx, p, p);
    fq(t, q::MUL, xxx, xx, p);
    fq(t, q::ADD, rhs, xxx, E::at(l.three));
    fq(t, q::MULEQ, rhs, yy, E::at(l.one));

    // `k = (k₁ − 2b₁k₁) + λ(k₂ − 2b₂k₂)`, each `b_i² = b_i`.
    let [k1, k2, b1, _, b2, _] = core::array::from_fn(|i| l.split + i as u32);
    let [w0, w1] = [l.work, l.work + 1];
    for bit in [b1, b2] {
        t.fr(fr_op::MUL, w0, bit, bit);
        t.assert_eq(w0, bit);
    }
    for (w, k, bit) in [(w0, k1, b1), (w1, k2, b2)] {
        t.fr(fr_op::MUL, w, bit, k);
        t.fr(fr_op::ADD, w, w, w);
        t.fr(fr_op::SUB, w, k, w);
    }
    t.fr(fr_op::MUL, w1, w1, l.lambda);
    t.fr(fr_op::ADD, w0, w0, w1);
    t.assert_eq(w0, l.scalar);
    for (half, k) in [k1, k2].into_iter().enumerate() {
        for w in 0..WINDOWS {
            let digit = l.digits + WINDOWS * half as u32 + w;
            t.fr(fr_op::DIGIT, digit, k, k);
        }
        t.assert_eq(k, ZERO);
    }

    // `s₂φ(P) = (β·x, y − 2b₂y)`, then `s₁P` in place, `y − 2b₁y`.
    let p2 = E::at(l.point2);
    fq(t, q::MUL, p2, E::at(l.beta), p);
    for (d, bit) in [(p2, b2), (p, b1)] {
        let (bq, m) = (fresh(t), fresh(t));
        fq(t, q::FROM128, bq, E::at(bit), E::at(l.zero));
        fq(t, q::MUL, m, bq, p.y());
        fq(t, q::ADD, m, m, m);
        fq(t, q::SUB, d.y(), p.y(), m);
    }
    for (half, point) in [p, p2].into_iter().enumerate() {
        let pairs: Vec<(E, E)> = (0..WINDOWS)
            .map(|w| {
                let digit = l.digits + WINDOWS * half as u32 + w;
                (
                    E {
                        word: l.bucket(w, 0),
                        digit: Some(digit),
                    },
                    point,
                )
            })
            .collect();
        b.batched_add(&pairs, E::at(l.one));
    }
    b.done()
}

/// `k`'s split, as [`point_template`] reads it from `split`:
/// `[|k₁|, |k₂|, b₁, 0, b₂, 0]` with `k ≡ s₁·|k₁| + λ·s₂·|k₂|`, `s_i = 1 − 2b_i`,
/// and each `|k_i| < 2^128` — Babai's rounding against [`BASIS`], the
/// quotients `⌊k·g_i / 2^256⌋` taken in integers.
pub fn split(k: Fr) -> [Fr; 6] {
    let bytes = k.to_bytes();
    let limbs: [u64; 4] = core::array::from_fn(|i| {
        u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().expect("8"))
    });
    let fr = |v: u128| Fr::from_u64(v as u64) + Fr::from_u64((v >> 64) as u64) * pow64();
    let signed = |(v, negative): (u128, bool)| if negative { -fr(v) } else { fr(v) };
    // `⌊k·g / 2^256⌋`: the product's limbs from the fourth up.
    let quotient = |g: &[u64; 3]| {
        let mut product = [0u64; 7];
        for (i, a) in limbs.iter().enumerate() {
            let mut carry = 0u128;
            for (j, b) in g.iter().enumerate() {
                let v = product[i + j] as u128 + (*a as u128) * (*b as u128) + carry;
                product[i + j] = v as u64;
                carry = v >> 64;
            }
            product[i + 3] = carry as u64;
        }
        fr(product[4] as u128 | (product[5] as u128) << 64)
            + fr(product[6] as u128) * pow64() * pow64()
    };
    let (c1, c2) = (quotient(&ROUND[0]), quotient(&ROUND[1]));
    let [a1, b1, a2, b2] = BASIS.map(signed);
    let halves = [k - c1 * a1 - c2 * a2, -(c1 * b1) - c2 * b2];
    let [(k1, n1), (k2, n2)] = halves.map(|v| {
        let small = |x: Fr| x.to_bytes()[16..].iter().all(|z| *z == 0);
        if small(v) {
            (v, Fr::ZERO)
        } else {
            assert!(small(-v), "fold: a split half is not below 2^128");
            (-v, Fr::ONE)
        }
    });
    [k1, k2, n1, Fr::ZERO, n2, Fr::ZERO]
}

/// The finish: each window's `T_w = Σ_b b·B_w[b]` by running sums, batched
/// across the windows, `b` the counter from 254 down; then `Σ_w 256^w·T_w`
/// by Horner, eight doublings and `T_w` added a step, the counter `2w`; then
/// `−R''`. The result is at `result`.
pub fn finish(l: &Layout) -> Vec<Phase> {
    let zero = E::at(l.zero);
    let one = E::at(l.one);
    let s = |w: u32| E::at(l.sums + 2 * POINT_CELLS * w);
    let tt = |w: u32| E::at(l.sums + 2 * POINT_CELLS * w + POINT_CELLS);
    let acc = E::at(l.result);

    let mut b = Build::new(l);
    for w in 0..WINDOWS {
        let top = E::at(l.bucket(w, BUCKETS - 1));
        copy_point(&mut b.t, s(w), top, zero);
        copy_point(&mut b.t, tt(w), top, zero);
    }
    b.t.fr(fr_op::IMM, l.counter, ZERO, BUCKETS - 2);
    let tops = b.done();

    let mut b = Build::new(l);
    let pairs: Vec<(E, E)> = (0..WINDOWS)
        .map(|w| (s(w), at_counter(l, l.bucket(w, 0))))
        .collect();
    b.batched_add(&pairs, one);
    let pairs: Vec<(E, E)> = (0..WINDOWS).map(|w| (tt(w), s(w))).collect();
    b.batched_add(&pairs, one);
    step(&mut b.t, l, 0, fr_op::SUB);
    let running = b.done();

    let mut b = Build::new(l);
    copy_point(&mut b.t, acc, tt(WINDOWS - 1), zero);
    b.t.fr(fr_op::IMM, l.counter, ZERO, 2 * (WINDOWS - 2));
    let top = b.done();

    let mut b = Build::new(l);
    for _ in 0..fr_op::DIGIT_BITS {
        b.double(acc, l);
    }
    b.batched_add(&[(acc, at_counter(l, tt(0).word))], one);
    step(&mut b.t, l, 1, fr_op::SUB);
    let horner = b.done();

    let mut b = Build::new(l);
    b.batched_add(&[(acc, E::at(l.correction))], one);
    let correction = b.done();

    alloc::vec![
        (tops, 1),
        (running, BUCKETS - 2),
        (top, 1),
        (horner, WINDOWS - 1),
        (correction, 1)
    ]
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
/// `[1]_2`, or `B`, with `[x]_2` (`docs/spec/mercury.md` §6.1).
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
/// constants, the merged points' scalars and limbs, the shard being folded's
/// scalars and a fold tape's scratch — field cells all, so a `FROM128`
/// reading past a shard's last limbs reads one of them — and then the two
/// MSMs.
///
/// **A merged point** is one every shard of a family owes, and so one the
/// node adds once: `[1]_1`, and each setup commitment of each family the node
/// verifies. Each shard's fold adds its share to the point's scalar, and the
/// point goes into the MSM after the last shard ([`merged_points`]).
#[derive(Clone, Copy, Debug)]
pub struct Node {
    /// The node transcript's state, three cells, carried from shard to shard.
    pub state: Cell,
    /// `[1]_1`'s four transcript limbs.
    pub generator: Cell,
    /// `G1_INFINITY_SENTINEL`.
    pub sentinel: Cell,
    /// The merged points' scalars, `[1]_1`'s first.
    pub merged: Cell,
    /// The merged setup commitments' limbs, four a point, in the order their
    /// families' [`shard_fold`]s name them.
    pub setup: Cell,
    /// How many there are.
    pub setups: u32,
    /// The shard being folded's point scalars, one cell a point.
    pub scalars: Cell,
    /// Where a fold tape's own cells start.
    pub scratch: Cell,
    pub a: Layout,
    pub b: Layout,
}

impl Node {
    /// The cells from `base` up: `setups` merged setup commitments, and room
    /// for `points` scalars a shard.
    pub fn at(base: Cell, setups: u32, points: u32) -> Node {
        let merged = base + 8;
        let setup = merged + 1 + setups;
        let scalars = setup + 4 * setups;
        let scratch = scalars + points;
        let a = Layout::at(scratch + SCRATCH);
        Node {
            state: base,
            generator: base + 3,
            sentinel: base + 7,
            merged,
            setup,
            setups,
            scalars,
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
/// check `cm* − Σ ρ^i·cm_i` folded beside the Mercury check. `[1]_1`'s and
/// the setup commitments' are added to the merged scalars, setup commitment
/// `j` being merged point `merged[j]`. Returns the tape and the rest of the
/// points, in the order a guest adds them.
pub fn shard_fold(shape: &ShardTape, node: &Node, merged: &[u32]) -> (Vec<Op>, Vec<FoldPoint>) {
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
        if *k == 9 {
            t.mac(node.merged, w, e[i]);
            continue;
        }
        add(&mut t, limbs(*k), side, &|t, c| {
            t.fr(fr_op::MUL, c, w, e[i]);
            if i == 0 {
                t.fr(fr_op::ADD, c, c, w2);
            }
        });
    }
    // The setup commitments are the batch's last.
    let own = out.commitments.len() - shape.slots.setup.len();
    for (j, (cm, rho)) in out.commitments.iter().zip(&out.batch).enumerate() {
        if j >= own {
            let m = node.merged + merged[j - own];
            let share = t.mul(w2, *rho);
            t.fr(fr_op::SUB, m, m, share);
            continue;
        }
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
pub fn load_point(p: &FoldPoint, l: &Layout, sentinel: Cell, infinity: bool) -> Load {
    if infinity {
        let ops = core::array::from_fn(|k| Op::Fr([fr_op::EQ, 0, p.limbs + k as u32, sentinel]));
        return Load { ops, n: 4 };
    }
    let ops = [
        Op::Fq([q::FROM128, l.point, p.limbs, l.zero]),
        Op::Fq([q::FROM128, l.point + 4, p.limbs + 2, l.zero]),
        Op::Fr([fr_op::ADD, l.scalar, p.scalar, ZERO]),
        Op::Fr([fr_op::EQ, 0, ZERO, ZERO]),
    ];
    Load { ops, n: 3 }
}

/// [`load_point`]'s ops, three or four, with no allocation: a node loads a
/// point for each it folds.
pub struct Load {
    ops: [Op; 4],
    n: usize,
}

impl core::ops::Deref for Load {
    type Target = [Op];
    fn deref(&self) -> &[Op] {
        &self.ops[..self.n]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A split's halves are below `2^128`, its sign bits bits, and it
    /// recomposes to its scalar — at the edges and at random.
    #[test]
    fn a_split_recomposes_its_scalar() {
        let lambda = Fr::from_hex(LAMBDA).expect("a canonical literal");
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let edges = [Fr::ZERO, Fr::ONE, -Fr::ONE, lambda, -lambda];
        let random = (0..1000).map(|_| {
            let limbs = [next(), next(), next(), next() >> 3];
            limbs
                .iter()
                .rev()
                .fold(Fr::ZERO, |acc, l| acc * pow64() + Fr::from_u64(*l))
        });
        for k in edges.into_iter().chain(random) {
            let [k1, k2, b1, z1, b2, z2] = split(k);
            for half in [k1, k2] {
                assert!(half.to_bytes()[16..].iter().all(|b| *b == 0), "{k:?}");
            }
            for bit in [b1, b2] {
                assert!(bit == Fr::ZERO || bit == Fr::ONE);
            }
            assert_eq!([z1, z2], [Fr::ZERO; 2]);
            let sign = |b: Fr| Fr::ONE - b - b;
            assert_eq!(sign(b1) * k1 + lambda * sign(b2) * k2, k);
        }
    }
}
