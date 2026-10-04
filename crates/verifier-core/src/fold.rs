//! The fold's MSM (`docs/spec/recursion.md` §8.3): `Σ_i s_i·P_i` over BN254's
//! G1 on `FQ_OP`, as tapes a guest replays from its image.
//!
//! Pippenger with 8-bit digits — 32 windows of 256 buckets — shaped so that
//! nothing a replay does depends on a value:
//!
//! - **A point** is one static template: its scalar's 32 `DIGIT`s, then one
//!   affine bucket addition in each window, the bucket an indirect operand
//!   through that window's digit cell. The 32 additions land in 32 windows,
//!   so they never collide, and share one inversion.
//! - **An inversion** is a host witness: the template reads it from two cells
//!   and asserts it with one `MULEQ`. [`simulate`] runs a template natively
//!   and fills every one, which is how a host lays a guest's witnesses out.
//! - **Bucket `b` starts at `(b + 1)·R`** for a fixed point `R`, so no
//!   addition meets infinity and no running sum adds a point to itself; the
//!   finish subtracts what the offsets added, once, at the end.
//! - **The finish** is static too: each window's running sums, batched across
//!   the 32 windows, then Horner over the windows by doubling.
//!
//! A point is two elements, `x` at its cell and `y` four cells on.

use alloc::vec::Vec;

use constants::{fq_op as q, fr_op};
use constraints::fq_op as arith;
use field::Fr;

use crate::tape::{Cell, Op, Tape, ZERO};

/// A scalar's digits, and the windows.
pub const WINDOWS: u32 = fr_op::DIGITS as u32;
/// A window's buckets, bucket 0 the digit-0 bucket no sum reads.
pub const BUCKETS: u32 = 1 << fr_op::DIGIT_BITS;
/// A point's cells: `x`, then `y`.
pub const POINT_CELLS: u32 = 2 * q::ELEMENT_CELLS as u32;

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
    /// Where each template's own cells start.
    pub scratch: Cell,
}

impl Layout {
    /// The cells from `base` up, in field order.
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
            scratch: take(0),
        }
    }

    /// Bucket `b` of window `w`.
    pub fn bucket(&self, w: u32, b: u32) -> Cell {
        self.buckets + POINT_CELLS * (BUCKETS * w + b)
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

/// The witness at a hole: `inv` from its two halves, asserted against `of`.
fn witness(t: &mut Tape, holes: &mut Vec<Hole>, of: E, one: E) -> E {
    let into = t.fresh(2);
    holes.push(Hole {
        at: t.ops.len(),
        of: of.word,
        into,
    });
    let inv = fresh(t);
    fq(t, q::FROM128, inv, E::at(into), E::at(one.word));
    // `inv·of ≡ 1`: `MULEQ` holds its `d` operand, the element 1.
    fq(t, q::MULEQ, one, inv, of);
    inv
}

/// `acc_k ← acc_k + add_k` for every pair, affine, one inversion between
/// them all. The pairs' accumulators are distinct points.
fn batched_add(t: &mut Tape, holes: &mut Vec<Hole>, pairs: &[(E, E)], one: E) {
    let n = pairs.len();
    let mut delta = Vec::with_capacity(n);
    let mut prefix: Vec<E> = Vec::with_capacity(n);
    for (k, (acc, add)) in pairs.iter().enumerate() {
        let dx = fresh(t);
        fq(t, q::SUB, dx, *acc, *add);
        delta.push(dx);
        if k == 0 {
            prefix.push(dx);
        } else {
            let p = fresh(t);
            fq(t, q::MUL, p, prefix[k - 1], dx);
            prefix.push(p);
        }
    }
    let mut inv = witness(t, holes, prefix[n - 1], one);
    let mut inverses = alloc::vec![inv; n];
    for k in (1..n).rev() {
        let own = fresh(t);
        fq(t, q::MUL, own, inv, prefix[k - 1]);
        inverses[k] = own;
        let next = fresh(t);
        fq(t, q::MUL, next, inv, delta[k]);
        inv = next;
    }
    inverses[0] = inv;
    for ((acc, add), inv) in pairs.iter().zip(inverses) {
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
}

/// `p ← 2p`, affine, its inversion a hole of its own.
fn double(t: &mut Tape, holes: &mut Vec<Hole>, p: E, l: &Layout) {
    let (xx, num, den, x3, sx, lam, lam2, u, v) = (
        fresh(t),
        fresh(t),
        fresh(t),
        fresh(t),
        fresh(t),
        fresh(t),
        fresh(t),
        fresh(t),
        fresh(t),
    );
    fq(t, q::MUL, xx, p, p);
    fq(t, q::MUL, num, xx, E::at(l.three));
    fq(t, q::ADD, den, p.y(), p.y());
    let inv = witness(t, holes, den, E::at(l.one));
    fq(t, q::MUL, lam, num, inv);
    fq(t, q::MUL, lam2, lam, lam);
    fq(t, q::ADD, sx, p, p);
    fq(t, q::SUB, x3, lam2, sx);
    fq(t, q::SUB, u, p, x3);
    fq(t, q::MUL, v, lam, u);
    fq(t, q::SUB, p.y(), v, p.y());
    fq(t, q::ADD, p, x3, E::at(l.zero));
}

/// A point's two coordinates from a constant's limbs.
fn constant_point(t: &mut Tape, at: Cell, point: &[[u64; 4]; 2], zero: E) {
    for (c, limbs) in point.iter().enumerate() {
        let element = E::at(at + c as u32 * q::ELEMENT_CELLS as u32);
        constant_element(t, element, limbs, zero);
    }
}

/// An element from a constant's limbs: its two 128-bit halves as cells, then
/// `FROM128`.
fn constant_element(t: &mut Tape, d: E, limbs: &[u64; 4], zero: E) {
    let lo = t.constant(Fr::from_u64(limbs[0]) + Fr::from_u64(limbs[1]) * pow64());
    let hi = t.constant(Fr::from_u64(limbs[2]) + Fr::from_u64(limbs[3]) * pow64());
    // `FROM128` reads its two halves as one operand's first two cells.
    let halves = t.fresh(2);
    t.ops.push(Op::Fr([fr_op::ADD, halves, lo, ZERO]));
    t.ops.push(Op::Fr([fr_op::ADD, halves + 1, hi, ZERO]));
    fq(t, q::FROM128, d, E::at(halves), zero);
}

fn pow64() -> Fr {
    Fr::from_u64(1 << 32) * Fr::from_u64(1 << 32)
}

/// `d ← p`, a point's two elements.
fn copy_point(t: &mut Tape, d: E, p: E, zero: E) {
    fq(t, q::ADD, d, p, zero);
    fq(t, q::ADD, d.y(), p.y(), zero);
}

/// Once an MSM: the constants, the offsets `(b + 1)·R` by a chain — `2R` a
/// doubling, every later one an addition of `R` to a different multiple —
/// and bucket `b` of every window set to `(b + 1)·R`.
pub fn prelude(l: &Layout) -> Template {
    let mut t = Tape::new(l.scratch);
    let mut holes = Vec::new();
    let zero = E::at(l.zero);
    constant_element(&mut t, E::at(l.one), &[1, 0, 0, 0], zero);
    constant_element(&mut t, E::at(l.three), &[3, 0, 0, 0], zero);
    constant_point(&mut t, l.offset, &OFFSET, zero);
    constant_point(&mut t, l.correction, &CORRECTION, zero);
    let offset = |b: u32| E::at(l.offsets + POINT_CELLS * b);
    copy_point(&mut t, offset(0), E::at(l.offset), zero);
    copy_point(&mut t, offset(1), E::at(l.offset), zero);
    double(&mut t, &mut holes, offset(1), l);
    for b in 2..BUCKETS {
        copy_point(&mut t, offset(b), offset(b - 1), zero);
        batched_add(
            &mut t,
            &mut holes,
            &[(offset(b), E::at(l.offset))],
            E::at(l.one),
        );
    }
    for w in 0..WINDOWS {
        for b in 0..BUCKETS {
            copy_point(&mut t, E::at(l.bucket(w, b)), offset(b), zero);
        }
    }
    Template { ops: t.ops, holes }
}

/// One point: its scalar's digits, then one bucket addition a window,
/// batched. The caller has put the point at `point` and the scalar at
/// `scalar`.
pub fn point_template(l: &Layout) -> Template {
    let mut t = Tape::new(l.scratch);
    let mut holes = Vec::new();
    for w in 0..WINDOWS {
        t.ops
            .push(Op::Fr([fr_op::DIGIT, l.digits + w, l.scalar, l.scalar]));
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
    batched_add(&mut t, &mut holes, &pairs, E::at(l.one));
    Template { ops: t.ops, holes }
}

/// The finish: each window's `T_w = Σ_b b·B_w[b]` by running sums, batched
/// across the windows; then `Σ_w 256^w·T_w` by Horner, doubling; then `−R''`.
/// The result is at `result`.
pub fn finish_template(l: &Layout) -> Template {
    let mut t = Tape::new(l.scratch);
    let mut holes = Vec::new();
    let zero = E::at(l.zero);
    let one = E::at(l.one);
    let s = |w: u32| E::at(l.sums + 2 * POINT_CELLS * w);
    let tt = |w: u32| E::at(l.sums + 2 * POINT_CELLS * w + POINT_CELLS);
    for w in 0..WINDOWS {
        let top = E::at(l.bucket(w, BUCKETS - 1));
        for acc in [s(w), tt(w)] {
            fq(&mut t, q::ADD, acc, top, zero);
            fq(&mut t, q::ADD, acc.y(), top.y(), zero);
        }
    }
    for b in (1..BUCKETS - 1).rev() {
        let pairs: Vec<(E, E)> = (0..WINDOWS)
            .map(|w| (s(w), E::at(l.bucket(w, b))))
            .collect();
        batched_add(&mut t, &mut holes, &pairs, one);
        let pairs: Vec<(E, E)> = (0..WINDOWS).map(|w| (tt(w), s(w))).collect();
        batched_add(&mut t, &mut holes, &pairs, one);
    }
    let acc = E::at(l.result);
    let top = tt(WINDOWS - 1);
    fq(&mut t, q::ADD, acc, top, zero);
    fq(&mut t, q::ADD, acc.y(), top.y(), zero);
    for w in (0..WINDOWS - 1).rev() {
        for _ in 0..fr_op::DIGIT_BITS {
            double(&mut t, &mut holes, acc, l);
        }
        batched_add(&mut t, &mut holes, &[(acc, tt(w))], one);
    }
    batched_add(&mut t, &mut holes, &[(acc, E::at(l.correction))], one);
    Template { ops: t.ops, holes }
}

/// Run `template` natively, filling every hole with its inverse; returns the
/// inverses in hole order — the words a guest imports — or the op that
/// refused.
pub fn simulate(template: &Template, memory: &mut Vec<Fr>) -> Result<Vec<[u64; 4]>, usize> {
    let mut witnesses = Vec::with_capacity(template.holes.len());
    let mut from = 0;
    for hole in &template.holes {
        crate::tape::run(&template.ops[from..hole.at], memory, &[]).map_err(|i| from + i)?;
        let mut element = [0u64; 4];
        for (k, limb) in element.iter_mut().enumerate() {
            *limb = memory
                .get(hole.of as usize + k)
                .and_then(|v| arith::limb(*v))
                .ok_or(hole.at)?;
        }
        let inv = arith::inv_mod_q(element);
        let halves = [
            Fr::from_u64(inv[0]) + Fr::from_u64(inv[1]) * pow64(),
            Fr::from_u64(inv[2]) + Fr::from_u64(inv[3]) * pow64(),
        ];
        for (k, half) in halves.into_iter().enumerate() {
            let cell = (hole.into + k as u32) as usize;
            if memory.len() <= cell {
                memory.resize(cell + 1, Fr::ZERO);
            }
            memory[cell] = half;
        }
        witnesses.push(inv);
        from = hole.at;
    }
    crate::tape::run(&template.ops[from..], memory, &[]).map_err(|i| from + i)?;
    Ok(witnesses)
}
