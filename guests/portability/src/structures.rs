//! Types, dispatch, closures, iterators, recursion and errors: the shape of
//! ordinary application Rust, as opposed to its arithmetic.
//!
//! What can differ between the host and the guest here is rarely a value a
//! program computes on purpose. It is the machinery underneath: a vtable call,
//! a `match` lowered to a jump table, an enum's niche, a `memcpy` of a
//! half-kilobyte struct passed by value, a `memcmp` behind a derived `Ord`, the drop glue of
//! an `Rc` graph, `amoadd.w` and `lr.w`/`sc.w` behind an atomic, the stack of a
//! deep recursion, and `core::fmt` building an error chain's text. Each feature
//! area is one section, so a mismatch names the machinery that broke.
//!
//! Every section is a function of the rng, the scale and the payload alone. No
//! `usize` is emitted without widening, and nothing sorted unstably can have
//! equal elements that are distinguishable.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::rc::{Rc, Weak};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::cmp::Ordering;
use core::fmt;
use core::hint::black_box;
use core::ops::{Add, AddAssign, Index, Mul, Neg};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering as AtomicOrdering};

use crate::{Ctx, Digest, Fault, Rng};

pub const TAGS: (u8, u8) = (0x40, 0x4f);

/// Enums, `match` in all its forms, and a stack machine over generated code.
pub const TAG_ENUMS: u8 = 0x40;
/// The machine's final state as text: the readable companion of [`TAG_ENUMS`].
pub const TAG_MACHINE: u8 = 0x41;
/// Trait objects, generics, associated items, operators and conversions.
pub const TAG_TRAITS: u8 = 0x42;
/// Closures captured every way, boxed, returned and composed.
pub const TAG_CLOSURES: u8 = 0x43;
/// Iterator adapters and the collections they collect into.
pub const TAG_ITERATORS: u8 = 0x44;
/// A `Box`-recursive expression tree under checked arithmetic.
pub const TAG_EXPR_TREE: u8 = 0x45;
/// A recursive-descent parser over generated text, and memoized mutual
/// recursion.
pub const TAG_PARSER: u8 = 0x46;
/// One deep recursion, and the recursive drop of a long `Box` list.
pub const TAG_DEEP: u8 = 0x47;
/// Large values moved, cloned, compared and sorted by value.
pub const TAG_LARGE: u8 = 0x48;
/// `Rc<RefCell<_>>` with `Weak` back-pointers, `Cell` and borrow states.
pub const TAG_SHARED: u8 = 0x49;
/// `Arc` and the atomics riscv32imac has.
pub const TAG_ATOMICS: u8 = 0x4a;
/// An error chain through `?`, `From`, `Box<dyn Error>` and the combinators.
pub const TAG_ERRORS: u8 = 0x4b;
/// The error chains [`TAG_ERRORS`] fingerprints, a few of them as text.
pub const TAG_ERROR_TEXT: u8 = 0x4c;

pub const FAULT_DOUBLE_BORROW: u8 = 0x40;
pub const FAULT_UNREACHABLE: u8 = 0x41;
pub const FAULT_FORMATTED: u8 = 0x42;
pub const FAULT_EXPECT: u8 = 0x43;

pub const FAULTS: &[Fault] = &[
    Fault {
        code: FAULT_DOUBLE_BORROW,
        what: "a `RefCell::borrow` of the root, reached from a leaf, while it is borrowed mutably",
    },
    Fault {
        code: FAULT_UNREACHABLE,
        what: "`unreachable!` on an opcode the machine's decoder was told never to see",
    },
    Fault {
        code: FAULT_FORMATTED,
        what: "`panic!` with a message formatted from the expression tree's values",
    },
    Fault {
        code: FAULT_EXPECT,
        what: "`Option::expect` on a lookup of a key the memo table does not hold",
    },
];

pub fn run(cx: &mut Ctx) {
    enums(cx);
    traits(cx);
    closures(cx);
    iterators(cx);
    expr_tree(cx);
    parser(cx);
    deep(cx);
    large(cx);
    shared(cx);
    atomics(cx);
    errors(cx);
}

/// At most `n` bytes of the payload. A payload can be kilobytes, and at the
/// guest's `opt-level = 0` decoding all of it would be most of the workload.
fn prefix(payload: &[u8], n: usize) -> &[u8] {
    &payload[..payload.len().min(n)]
}

// ---------------------------------------------------------------------------
// Enums and the stack machine
// ---------------------------------------------------------------------------

/// Explicit, sparse discriminants, so an `as` cast and a `match` on the enum
/// lower to different code: the cast reads the tag, the match may build a jump
/// table over it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
enum Op {
    Push = 1,
    Add = 2,
    Sub = 3,
    Mul = 5,
    Dup = 8,
    Swap = 13,
    Drop = 21,
    Jz = 34,
    Jmp = 55,
    Call = 89,
    Ret = 144,
    Halt = 233,
}

impl Op {
    const ALL: [Op; 12] = [
        Op::Push,
        Op::Add,
        Op::Sub,
        Op::Mul,
        Op::Dup,
        Op::Swap,
        Op::Drop,
        Op::Jz,
        Op::Jmp,
        Op::Call,
        Op::Ret,
        Op::Halt,
    ];

    /// The inverse of `as u8`, through a `match` on ranges of the tag rather
    /// than a table, so a tag between two discriminants takes the error path.
    fn from_tag(tag: u8) -> Option<Op> {
        match tag {
            1 => Some(Op::Push),
            2 | 3 => Some(if tag == 2 { Op::Add } else { Op::Sub }),
            5 => Some(Op::Mul),
            8 => Some(Op::Dup),
            13 => Some(Op::Swap),
            21 => Some(Op::Drop),
            34 => Some(Op::Jz),
            55 => Some(Op::Jmp),
            89 => Some(Op::Call),
            144 => Some(Op::Ret),
            233 => Some(Op::Halt),
            0 | 4 | 6..=7 | 9..=12 | 14..=20 | 22..=33 | 35..=54 => None,
            56..=88 | 90..=143 | 145..=232 | 234..=u8::MAX => None,
        }
    }
}

/// An instruction: data-carrying variants, one of them nesting another enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Instr {
    Push(i32),
    Arith(Op),
    Stack(Op),
    Branch { op: Op, target: u16 },
    Call(u16),
    Ret,
    Halt,
}

/// Why the machine stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Stop {
    Halted,
    Underflow { pc: u16, op: Op },
    Overflow(i32, i32),
    OutOfFuel,
    FellOff(u16),
    CallDepth,
}

struct Machine<'p> {
    program: &'p [Instr],
    stack: Vec<i32>,
    frames: Vec<u16>,
    pc: u16,
    steps: u32,
}

impl Machine<'_> {
    fn pop2(&mut self, op: Op) -> Result<(i32, i32), Stop> {
        // Slice patterns on the stack's top: `[.., a, b]` binds the last two.
        match self.stack.as_slice() {
            [.., a, b] => {
                let pair = (*a, *b);
                self.stack.truncate(self.stack.len() - 2);
                Ok(pair)
            }
            [] | [_] => Err(Stop::Underflow { pc: self.pc, op }),
        }
    }

    fn step(&mut self) -> Result<(), Stop> {
        let Some(&instr) = self.program.get(usize::from(self.pc)) else {
            return Err(Stop::FellOff(self.pc));
        };
        let here = self.pc;
        self.pc += 1;
        match instr {
            Instr::Push(v) => self.stack.push(v),
            Instr::Arith(op @ (Op::Add | Op::Sub | Op::Mul)) => {
                let (a, b) = self.pop2(op)?;
                let r = match op {
                    Op::Add => a.checked_add(b),
                    Op::Sub => a.checked_sub(b),
                    _ => a.checked_mul(b),
                };
                self.stack.push(r.ok_or(Stop::Overflow(a, b))?);
            }
            Instr::Stack(Op::Dup) => match self.stack.last() {
                Some(&top) => self.stack.push(top),
                None => {
                    return Err(Stop::Underflow {
                        pc: here,
                        op: Op::Dup,
                    })
                }
            },
            Instr::Stack(Op::Swap) => {
                let (a, b) = self.pop2(Op::Swap)?;
                self.stack.extend([b, a]);
            }
            Instr::Stack(op) | Instr::Arith(op) => {
                // Drop, and any operator the generator put in the wrong
                // variant, which pops one or underflows.
                if self.stack.pop().is_none() {
                    return Err(Stop::Underflow { pc: here, op });
                }
            }
            Instr::Branch { op: Op::Jz, target } => {
                let Some(top) = self.stack.pop() else {
                    return Err(Stop::Underflow {
                        pc: here,
                        op: Op::Jz,
                    });
                };
                if top == 0 {
                    self.pc = target;
                }
            }
            Instr::Branch { target, .. } => self.pc = target,
            Instr::Call(target) if self.frames.len() < 16 => {
                self.frames.push(self.pc);
                self.pc = target;
            }
            Instr::Call(_) => return Err(Stop::CallDepth),
            Instr::Ret => match self.frames.pop() {
                Some(back) => self.pc = back,
                None => return Err(Stop::Halted),
            },
            Instr::Halt => return Err(Stop::Halted),
        }
        Ok(())
    }

    fn run(&mut self, fuel: u32) -> Stop {
        while self.steps < fuel {
            self.steps += 1;
            if let Err(stop) = self.step() {
                return stop;
            }
        }
        Stop::OutOfFuel
    }
}

fn gen_instr(rng: &mut Rng, len: u16) -> Instr {
    let op = Op::ALL[rng.index(Op::ALL.len())];
    let target = rng.below(u64::from(len) + 2) as u16;
    match op {
        Op::Push => Instr::Push(rng.next_u32() as i32 >> rng.below(31)),
        Op::Add | Op::Sub | Op::Mul => Instr::Arith(op),
        Op::Dup | Op::Swap | Op::Drop => Instr::Stack(op),
        Op::Jz | Op::Jmp => Instr::Branch { op, target },
        Op::Call => Instr::Call(target),
        Op::Ret => Instr::Ret,
        Op::Halt => Instr::Halt,
    }
}

/// A classifier with every pattern form the machine does not already use:
/// char ranges, `@` bindings with ranges, nested tuple/struct destructuring,
/// `ref`/`ref mut`, and guards.
fn classify(word: u32, c: char, pair: &mut (i16, Option<(u8, char)>)) -> u32 {
    let kind = match c {
        'a'..='z' => 1,
        'A'..='Z' => 2,
        d @ '0'..='9' => 10 + d as u32 - '0' as u32,
        ' ' | '\t' | '\n' => 3,
        '\u{80}'..='\u{7ff}' => 4,
        _ => 5,
    };
    let size = match word {
        0 => 0,
        n @ 1..=0xff => n & 7,
        n @ 0x100..=0xffff if n % 2 == 0 => 20,
        0x100..=0xffff => 21,
        n => n.leading_zeros() + 30,
    };
    let nested = match pair {
        (n, Some((b, ch))) if *n < 0 && ch.is_alphabetic() => {
            *b = b.wrapping_add(1);
            100 + u32::from(*b)
        }
        (ref mut n, Some((_, ref ch))) => {
            *n = n.wrapping_add(*ch as i16);
            200
        }
        (n, None) => {
            *n = n.wrapping_neg();
            300
        }
    };
    kind * 1_000_000 + size * 1_000 + nested
}

fn enums(cx: &mut Ctx) {
    let mut d = Digest::new();

    // Discriminants through `as`, back through `from_tag`, and the derived
    // `Ord`, which orders by discriminant.
    for op in Op::ALL {
        let tag = op as u8;
        d.u8(tag).u8(Op::from_tag(tag).map_or(0xff, |o| o as u8));
    }
    let mut none = 0u32;
    for tag in (0..=u8::MAX).step_by(9) {
        if Op::from_tag(black_box(tag)).is_none() {
            none += 1;
        }
    }
    d.u32(none);
    let mut ops = Op::ALL;
    ops.rotate_left(5);
    ops.sort();
    d.bytes(&ops.map(|o| o as u8));

    // `classify` over the payload's characters, each paired with a word.
    let text = String::from_utf8_lossy(prefix(cx.payload(), 48));
    let mut pair: (i16, Option<(u8, char)>) = (-1, None);
    let chars = 8 + 2 * cx.scale() as usize;
    for (i, c) in text.chars().take(chars).enumerate() {
        let word = cx.rng().next_u32() >> (i % 32);
        pair.1 = if i % 3 == 0 { None } else { Some((i as u8, c)) };
        d.u32(classify(word, c, &mut pair));
    }
    d.u16(pair.0 as u16);

    // Programs for the machine: every stop reason, counted, and the machine's
    // state at the end of the last.
    let programs = 2 + cx.scale() / 2;
    let fuel = 24 + 12 * cx.scale();
    let mut stops = [0u32; 6];
    let mut last = String::new();
    let mut last_len = 0;
    for p in 0..programs {
        let len = 12 + cx.rng().below(20) as u16;
        let program: Vec<Instr> = (0..len).map(|_| gen_instr(cx.rng(), len)).collect();
        last_len = program.len();
        let mut m = Machine {
            program: &program,
            stack: Vec::new(),
            frames: Vec::new(),
            pc: 0,
            steps: 0,
        };
        let stop = m.run(fuel);
        let slot = match &stop {
            Stop::Halted => 0,
            Stop::Underflow { .. } => 1,
            Stop::Overflow(..) => 2,
            Stop::OutOfFuel => 3,
            Stop::FellOff(_) => 4,
            Stop::CallDepth => 5,
        };
        stops[slot] += 1;
        d.u32(m.steps).u16(m.pc).count(m.stack.len());
        for v in &m.stack {
            d.i32(*v);
        }
        if matches!(
            stop,
            Stop::Underflow {
                op: Op::Swap | Op::Add,
                ..
            }
        ) {
            d.u8(0x5a);
        }
        // `while let` draining the frame stack.
        while let Some(back) = m.frames.pop() {
            d.u16(back);
        }
        if p + 1 == programs {
            let top = match m.stack.as_slice() {
                [] => String::from("empty"),
                [only] => format!("[{only}]"),
                [first, .., last] => format!("[{first} .. {last}; {}]", m.stack.len()),
            };
            last = format!("stop {stop:?}, {} steps, pc {}, stack {top}", m.steps, m.pc);
        }
    }
    for s in stops {
        d.u32(s);
    }
    cx.digest(TAG_ENUMS, &d);

    if cx.fault(FAULT_UNREACHABLE) {
        // Re-decoding the last program's length as an opcode tag: 0xf0 and up
        // is a tag no generator emits, so the `None` arm is the one taken, at a
        // tag that depends on the program.
        let seen = black_box(last_len as u8) | 0xf0;
        match Op::from_tag(seen) {
            Some(op) => d.u8(op as u8),
            None => unreachable!("opcode tag {seen:#04x} after {programs} programs"),
        };
    }

    let text = format!("{last}; stops {stops:?}");
    cx.section(TAG_MACHINE, text.as_bytes());
}

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

/// A supertrait, so a `dyn Shape` vtable carries `Named`'s entries too.
trait Named {
    fn name(&self) -> &'static str;
}

trait Shape: Named {
    /// Twice the area, so every shape here stays in integers.
    fn area2(&self) -> i64;
    fn perimeter(&self) -> i64;
    /// A default method, overridden by one impl only.
    fn signature(&self) -> i64 {
        self.area2() * 31 + self.perimeter()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
struct Rect {
    w: i32,
    h: i32,
}

struct Tri([(i32, i32); 3]);

struct Poly(Vec<(i32, i32)>);

/// A shape wrapping another behind a box: a vtable call inside a vtable call.
struct Scaled(Box<dyn Shape>, i64);

impl Named for Rect {
    fn name(&self) -> &'static str {
        "rect"
    }
}
impl Named for Tri {
    fn name(&self) -> &'static str {
        "tri"
    }
}
impl Named for Poly {
    fn name(&self) -> &'static str {
        "poly"
    }
}
impl Named for Scaled {
    fn name(&self) -> &'static str {
        "scaled"
    }
}

impl Shape for Rect {
    fn area2(&self) -> i64 {
        2 * i64::from(self.w) * i64::from(self.h)
    }
    fn perimeter(&self) -> i64 {
        2 * (i64::from(self.w) + i64::from(self.h))
    }
}

/// The shoelace formula over a closed polygon: twice the signed area.
fn shoelace(points: &[(i32, i32)]) -> i64 {
    let n = points.len();
    (0..n)
        .map(|i| {
            let (x0, y0) = points[i];
            let (x1, y1) = points[(i + 1) % n];
            i64::from(x0) * i64::from(y1) - i64::from(x1) * i64::from(y0)
        })
        .sum::<i64>()
        .abs()
}

/// Manhattan perimeter, to stay out of square roots.
fn manhattan(points: &[(i32, i32)]) -> i64 {
    points
        .iter()
        .zip(points.iter().cycle().skip(1))
        .map(|(a, b)| i64::from((a.0 - b.0).abs() + (a.1 - b.1).abs()))
        .sum()
}

impl Shape for Tri {
    fn area2(&self) -> i64 {
        shoelace(&self.0)
    }
    fn perimeter(&self) -> i64 {
        manhattan(&self.0)
    }
}

impl Shape for Poly {
    fn area2(&self) -> i64 {
        shoelace(&self.0)
    }
    fn perimeter(&self) -> i64 {
        manhattan(&self.0)
    }
    fn signature(&self) -> i64 {
        self.area2() ^ (self.perimeter() << 20) ^ self.0.len() as i64
    }
}

impl Shape for Scaled {
    fn area2(&self) -> i64 {
        self.0.area2() * self.1 * self.1
    }
    fn perimeter(&self) -> i64 {
        self.0.perimeter() * self.1
    }
}

/// A trait with an associated type and const, implemented at three widths.
trait Lanes {
    type Word: Copy + Into<u64>;
    const BITS: u32;
    fn lane(x: u64, i: u32) -> Self::Word;
}

struct L8;
struct L16;
struct L32;

impl Lanes for L8 {
    type Word = u8;
    const BITS: u32 = 8;
    fn lane(x: u64, i: u32) -> u8 {
        (x >> (i * Self::BITS)) as u8
    }
}
impl Lanes for L16 {
    type Word = u16;
    const BITS: u32 = 16;
    fn lane(x: u64, i: u32) -> u16 {
        (x >> (i * Self::BITS)) as u16
    }
}
impl Lanes for L32 {
    type Word = u32;
    const BITS: u32 = 32;
    fn lane(x: u64, i: u32) -> u32 {
        (x >> (i * Self::BITS)) as u32
    }
}

/// Monomorphized once per `Lanes`: the associated const bounds the loop.
fn lane_sum<L: Lanes>(x: u64) -> u64 {
    (0..64 / L::BITS).map(|i| L::lane(x, i).into()).sum()
}

/// A generic function behind several bounds, monomorphized for four types.
fn weighted<T: Copy + Into<i64> + Ord>(xs: &[T]) -> i64 {
    let max = xs.iter().copied().max().map_or(0, Into::into);
    xs.iter()
        .enumerate()
        .map(|(i, x)| (i as i64 + 1) * (*x).into())
        .sum::<i64>()
        ^ max
}

/// A visitor behind a trait object, driven by a generic walker that is
/// instantiated both for the concrete type and for `dyn Visitor`.
trait Visitor {
    fn visit(&mut self, v: u32);
    fn done(&self) -> u64;
}

struct Xor(u32);
struct Hist([u16; 8]);

impl Visitor for Xor {
    fn visit(&mut self, v: u32) {
        self.0 = self.0.rotate_left(7) ^ v;
    }
    fn done(&self) -> u64 {
        u64::from(self.0)
    }
}

impl Visitor for Hist {
    fn visit(&mut self, v: u32) {
        self.0[(v % 8) as usize] += 1;
    }
    fn done(&self) -> u64 {
        self.0
            .iter()
            .fold(0u64, |acc, &c| acc.wrapping_mul(1009) + u64::from(c))
    }
}

fn walk<V: Visitor + ?Sized>(v: &mut V, items: &[u32]) -> u64 {
    for &x in items {
        v.visit(x);
    }
    v.done()
}

/// Arithmetic mod the largest 16-bit prime, with the operators overloaded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Gf(u32);

const GF_P: u32 = 65_521;

impl Add for Gf {
    type Output = Gf;
    fn add(self, rhs: Gf) -> Gf {
        Gf((self.0 + rhs.0) % GF_P)
    }
}
impl Mul for Gf {
    type Output = Gf;
    fn mul(self, rhs: Gf) -> Gf {
        Gf(self.0 * rhs.0 % GF_P)
    }
}
impl Neg for Gf {
    type Output = Gf;
    fn neg(self) -> Gf {
        Gf((GF_P - self.0) % GF_P)
    }
}
impl AddAssign for Gf {
    fn add_assign(&mut self, rhs: Gf) {
        *self = *self + rhs;
    }
}

/// A 2x2 matrix over [`Gf`], indexed by `(row, col)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct M2([[Gf; 2]; 2]);

impl Index<(usize, usize)> for M2 {
    type Output = Gf;
    fn index(&self, (r, c): (usize, usize)) -> &Gf {
        &self.0[r][c]
    }
}

impl Mul for M2 {
    type Output = M2;
    fn mul(self, rhs: M2) -> M2 {
        let mut out = M2::default();
        for r in 0..2 {
            for c in 0..2 {
                let mut acc = Gf::default();
                for k in 0..2 {
                    acc += self[(r, k)] * rhs[(k, c)];
                }
                out.0[r][c] = acc;
            }
        }
        out
    }
}

/// Hand-written `Ord`: longer first, then reverse lexicographic. Every field
/// takes part, so equal values are identical and even an unstable sort's
/// order is defined.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ByLen(Vec<u8>);

impl Ord for ByLen {
    fn cmp(&self, other: &ByLen) -> Ordering {
        other
            .0
            .len()
            .cmp(&self.0.len())
            .then_with(|| other.0.cmp(&self.0))
    }
}
impl PartialOrd for ByLen {
    fn partial_cmp(&self, other: &ByLen) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A percentage, whose `TryFrom` refuses more than 100.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Percent(u8);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TooLarge(u32);

impl TryFrom<u32> for Percent {
    type Error = TooLarge;
    fn try_from(v: u32) -> Result<Percent, TooLarge> {
        if v <= 100 {
            Ok(Percent(v as u8))
        } else {
            Err(TooLarge(v))
        }
    }
}

impl From<Percent> for u32 {
    fn from(p: Percent) -> u32 {
        u32::from(p.0)
    }
}

impl From<Rect> for Poly {
    fn from(r: Rect) -> Poly {
        Poly(vec![(0, 0), (r.w, 0), (r.w, r.h), (0, r.h)])
    }
}

/// `lo, lo + step, ...` below `hi`, from both ends: a custom iterator with
/// `DoubleEndedIterator` and an exact length.
struct Stride {
    lo: u32,
    hi: u32,
    step: u32,
}

impl Iterator for Stride {
    type Item = u32;
    fn next(&mut self) -> Option<u32> {
        if self.lo >= self.hi {
            return None;
        }
        let v = self.lo;
        self.lo += self.step;
        Some(v)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = if self.lo >= self.hi {
            0
        } else {
            ((self.hi - self.lo).div_ceil(self.step)) as usize
        };
        (n, Some(n))
    }
}

impl DoubleEndedIterator for Stride {
    fn next_back(&mut self) -> Option<u32> {
        if self.lo >= self.hi {
            return None;
        }
        let n = (self.hi - self.lo).div_ceil(self.step);
        let v = self.lo + (n - 1) * self.step;
        self.hi = v;
        Some(v)
    }
}

impl ExactSizeIterator for Stride {}

/// `impl Trait` in argument position.
fn total(items: impl Iterator<Item = u32>) -> u64 {
    items.map(u64::from).sum()
}

/// `impl Trait` in return position: the iterator's type is unnameable.
fn multiples(of: u32, below: u32) -> impl DoubleEndedIterator<Item = u32> + ExactSizeIterator {
    Stride {
        lo: 0,
        hi: below,
        step: of.max(1),
    }
}

fn traits(cx: &mut Ctx) {
    let mut d = Digest::new();
    let rounds = 1 + cx.scale() / 2;
    let small = |rng: &mut Rng| 1 + rng.below(40) as i32;

    for _ in 0..rounds {
        let mut shapes: Vec<Box<dyn Shape>> = Vec::new();
        for k in 0..4 {
            let rng = cx.rng();
            let shape: Box<dyn Shape> = match k {
                0 => Box::new(Rect {
                    w: small(rng),
                    h: small(rng),
                }),
                1 => Box::new(Tri([
                    (small(rng), -small(rng)),
                    (-small(rng), small(rng)),
                    (small(rng), small(rng)),
                ])),
                2 => {
                    let r = Rect {
                        w: small(rng),
                        h: small(rng),
                    };
                    Box::new(Poly::from(r))
                }
                _ => Box::new(Scaled(
                    Box::new(Rect {
                        w: small(rng),
                        h: 3,
                    }),
                    i64::from(small(rng)),
                )),
            };
            shapes.push(shape);
        }
        for s in &shapes {
            d.str(s.name()).i64(s.area2()).i64(s.signature());
        }
        let largest = shapes
            .iter()
            .max_by_key(|s| (s.area2(), s.perimeter()))
            .map(|s| s.name());
        d.str(largest.unwrap_or("none"));

        let x = cx.rng().next_u64();
        d.u64(lane_sum::<L8>(x))
            .u64(lane_sum::<L16>(x))
            .u64(lane_sum::<L32>(x));

        let raw = cx.rng().bytes(12);
        let bytes: Vec<u8> = raw.clone();
        let shorts: Vec<i16> = raw
            .chunks(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();
        let words: Vec<u32> = raw
            .chunks(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        let signed: Vec<i32> = words.iter().map(|w| *w as i32 >> 3).collect();
        d.i64(weighted(&bytes))
            .i64(weighted(&shorts))
            .i64(weighted(&words))
            .i64(weighted(&signed));

        let mut xor = Xor(1);
        let mut hist = Hist([0; 8]);
        d.u64(walk(&mut xor, &words));
        let dynamic: &mut dyn Visitor = &mut hist;
        d.u64(walk(dynamic, &words));
        let mut visitors: Vec<Box<dyn Visitor>> = vec![Box::new(Xor(7)), Box::new(Hist([1; 8]))];
        for v in visitors.iter_mut() {
            d.u64(walk(v.as_mut(), &words[1..]));
        }
    }

    // Operators: a matrix power by squaring, and the ring laws on `Gf`.
    let mut m = M2::default();
    for r in 0..2 {
        for c in 0..2 {
            m.0[r][c] = Gf(cx.rng().below(u64::from(GF_P)) as u32);
        }
    }
    let mut acc = M2([[Gf(1), Gf(0)], [Gf(0), Gf(1)]]);
    let mut base = m;
    let bits = 2 + cx.scale() / 2;
    let mut e = 5 + cx.rng().below(1 << bits);
    while e > 0 {
        if e & 1 == 1 {
            acc = acc * base;
        }
        base = base * base;
        e >>= 1;
    }
    for row in acc.0 {
        for g in row {
            d.u32(g.0);
        }
    }
    let (a, b) = (m[(0, 1)], m[(1, 1)]);
    d.u8(u8::from(a + -a == Gf(0))).u32((a * b + -b).0);

    // Orders: derived on `Rect`, hand-written on `ByLen`.
    let mut rects: Vec<Rect> = (0..8)
        .map(|_| Rect {
            w: cx.rng().below(4) as i32,
            h: cx.rng().below(4) as i32,
        })
        .collect();
    rects.sort_unstable();
    for r in &rects {
        d.i32(r.w).i32(r.h);
    }
    d.u8(Rect::default().cmp(&rects[0]) as u8);
    let mut words: Vec<ByLen> = (0..6)
        .map(|_| {
            let len = cx.rng().index(4);
            ByLen((0..len).map(|_| b'a' + cx.rng().below(3) as u8).collect())
        })
        .collect();
    words.sort_unstable();
    for w in &words {
        d.count(w.0.len()).bytes(&w.0);
    }
    d.u8(match words[0].partial_cmp(&words[words.len() - 1]) {
        Some(Ordering::Less) => 1,
        Some(Ordering::Equal) => 2,
        Some(Ordering::Greater) => 3,
        None => 4,
    });

    // Conversions, the error paths included.
    for _ in 0..2 + cx.scale() / 4 {
        let v = cx.rng().below(160) as u32;
        match Percent::try_from(v) {
            Ok(p) => d.u32(u32::from(p) + 1000),
            Err(TooLarge(v)) => d.u32(v + 2000),
        };
        let wide = cx.rng().next_u32() as i32 >> cx.rng().below(32);
        let narrow: Result<u8, _> = wide.try_into();
        let back: i64 = narrow.map_or(-1, i64::from);
        d.i64(back);
        let as_u16 = u16::try_from(wide).ok();
        d.u32(as_u16.map_or(u32::MAX, u32::from));
    }

    // The custom iterator from both ends and its exact length.
    let of = 1 + cx.rng().below(9) as u32;
    let span = 40 + 10 * u64::from(cx.scale());
    let below = 20 + cx.rng().below(span) as u32;
    let mut it = multiples(of, below);
    d.count(it.len());
    let front = it.next();
    let back = it.next_back();
    d.u32(front.unwrap_or(0))
        .u32(back.unwrap_or(0))
        .count(it.len());
    d.u64(total(it.rev().step_by(2)));
    d.u64(total(multiples(of + 1, below).skip(3)));
    cx.digest(TAG_TRAITS, &d);
}

// ---------------------------------------------------------------------------
// Closures
// ---------------------------------------------------------------------------

/// A closure returned by value, capturing its argument by move.
fn affine(a: i64, b: i64) -> impl Fn(i64) -> i64 {
    move |x| a.wrapping_mul(x).wrapping_add(b)
}

/// Composition of two closures into a third.
fn compose<A, B, C>(f: impl Fn(A) -> B, g: impl Fn(B) -> C) -> impl Fn(A) -> C {
    move |x| g(f(x))
}

/// Consumes an `FnOnce`: the closure moves out what it captured.
fn call_once<F: FnOnce() -> Vec<u8>>(f: F) -> Vec<u8> {
    f()
}

/// A closure behind `&mut dyn FnMut`, called in a loop.
fn drive(f: &mut dyn FnMut(u32) -> bool, items: &[u32]) -> u32 {
    let mut kept = 0;
    for &x in items {
        if f(x) {
            kept += 1;
        }
    }
    kept
}

fn closures(cx: &mut Ctx) {
    let mut d = Digest::new();
    let n = 6 + 6 * cx.scale() as usize;
    let data: Vec<u32> = (0..n).map(|_| cx.rng().next_u32() >> 20).collect();

    // By shared reference: the closure borrows `data`, which stays usable.
    let below = |t: u32| data.iter().filter(|&&y| y < t).count();
    d.count(below(1 << 11)).count(below(100));

    // By mutable reference: the closure is `FnMut`, and `seen` is readable
    // once it is gone.
    let mut seen = Vec::new();
    let mut record = |x: u32| {
        if x.is_multiple_of(3) {
            seen.push(x);
            true
        } else {
            false
        }
    };
    let kept = drive(&mut record, &data);
    d.u32(kept).count(seen.len());
    for s in &seen {
        d.u32(*s);
    }

    // By move: the key is copied in, the vector moved in and out once.
    let key = cx.rng().next_u32();
    let mask = move |x: u32| x ^ key;
    let owned: Vec<u8> = data.iter().map(|x| (mask(*x) >> 3) as u8).collect();
    let consumed = call_once(move || {
        let mut v = owned;
        v.reverse();
        v
    });
    d.bytes(&consumed);

    // Boxed `Fn`s in a vector, each capturing something different.
    let offset = i64::from(key % 1000);
    let factor = 3 + i64::from(key % 7);
    let table: Vec<Box<dyn Fn(i64) -> i64>> = vec![
        Box::new(move |x| x + offset),
        Box::new(move |x| x * factor),
        Box::new(|x| -x),
        Box::new(affine(factor, -offset)),
        Box::new(compose(affine(2, 1), move |y: i64| {
            y.rem_euclid(factor + 11)
        })),
        Box::new(compose(|x: i64| x as u8, |b: u8| i64::from(b.count_ones()))),
    ];
    let mut x = i64::from(data[0]);
    for (i, f) in table.iter().cycle().take(3 * table.len()).enumerate() {
        x = f(x) % 1_000_003 + i as i64;
        d.i64(x);
    }

    // Boxed `FnMut`s with their own state, called round-robin.
    let mut counters: Vec<Box<dyn FnMut(u32) -> u32>> = Vec::new();
    for k in 0..4u32 {
        let mut state = k;
        counters.push(Box::new(move |v| {
            state = state.wrapping_mul(31).wrapping_add(v);
            state
        }));
    }
    let len = counters.len();
    for (i, v) in data.iter().enumerate() {
        d.u32(counters[i % len](*v));
    }

    // A closure-driven pipeline: `scan` keeps a running state, `fold` folds
    // it, and `try_fold` stops at the first overflow.
    let step = affine(i64::from(key % 5) + 2, 1);
    let scanned: Vec<i64> = data
        .iter()
        .scan(0i64, |acc, &v| {
            *acc = step(*acc % 65_536) + i64::from(v);
            Some(*acc)
        })
        .collect();
    let folded = scanned
        .iter()
        .fold(0u64, |h, &v| h.rotate_left(9) ^ v as u64);
    let overflowed = data
        .iter()
        .try_fold(1u32, |acc, &v| acc.checked_mul(v.max(2)));
    d.u64(folded)
        .u32(overflowed.unwrap_or(0))
        .u8(u8::from(overflowed.is_none()));
    cx.digest(TAG_CLOSURES, &d);
}

// ---------------------------------------------------------------------------
// Iterators
// ---------------------------------------------------------------------------

fn iterators(cx: &mut Ctx) {
    let mut d = Digest::new();
    let n = 8 + 10 * cx.scale() as usize;
    let xs: Vec<i32> = (0..n)
        .map(|_| (cx.rng().next_u32() >> 22) as i32 - 512)
        .collect();
    let text = String::from_utf8_lossy(prefix(cx.payload(), 48));

    let mapped: Vec<i64> = xs
        .iter()
        .map(|&x| i64::from(x) * 3)
        .filter(|x| x % 2 == 0)
        .collect();
    d.count(mapped.len()).i64(mapped.iter().sum());

    let digits: Vec<u32> = text.chars().filter_map(|c| c.to_digit(16)).collect();
    d.count(digits.len()).u32(digits.iter().sum());

    let spread: Vec<i32> = xs.iter().take(8).flat_map(|&x| [x, -x, x / 3]).collect();
    let flat: i64 = vec![xs.clone(), spread.clone(), Vec::new()]
        .into_iter()
        .flatten()
        .map(i64::from)
        .sum();
    d.count(spread.len()).i64(flat);

    let running: Vec<i32> = xs
        .iter()
        .scan(0, |s, &x| {
            *s += x;
            Some(*s)
        })
        .take_while(|s| s.abs() < 3000)
        .collect();
    let rest: Vec<&i32> = xs.iter().skip_while(|x| **x < 200).collect();
    let small: Vec<u8> = xs.iter().map_while(|&x| u8::try_from(x).ok()).collect();
    d.count(running.len())
        .count(rest.len())
        .count(small.len())
        .bytes(&small);

    let stepped: i64 = xs.iter().step_by(3).map(|&x| i64::from(x)).sum();
    let chained = xs
        .iter()
        .take(3)
        .chain(xs.iter().rev().take(3))
        .fold(0i64, |a, &x| a * 7 + i64::from(x));
    let dot: i64 = xs
        .iter()
        .zip(xs.iter().skip(1))
        .map(|(a, b)| i64::from(*a) * i64::from(*b))
        .sum();
    d.i64(stepped).i64(chained).i64(dot);

    // `peekable`: runs of equal sign.
    let mut runs = 0u32;
    let mut it = xs.iter().peekable();
    while let Some(x) = it.next() {
        while it.next_if(|y| (**y < 0) == (*x < 0)).is_some() {}
        runs += 1;
        if let Some(&&next) = it.peek() {
            d.i32(next);
        }
    }
    d.u32(runs);

    // `fuse` over an iterator that would resume after `None`.
    let mut calls = 0u32;
    let flaky = core::iter::from_fn(|| {
        calls += 1;
        if calls.is_multiple_of(3) {
            None
        } else {
            Some(calls)
        }
    });
    let fused: Vec<u32> = flaky.fuse().take(10).collect();
    d.count(fused.len()).u32(fused.iter().sum());

    let cyc: Vec<i32> = xs.iter().copied().take(5).cycle().take(17).collect();
    let mut inspected = 0i64;
    let rev_sum: i64 = cyc
        .iter()
        .rev()
        .inspect(|x| inspected += i64::from(**x))
        .map(|&x| i64::from(x))
        .sum();
    d.i64(rev_sum).i64(inspected);

    let product: i64 = xs.iter().take(6).map(|&x| i64::from(x % 50) + 60).product();
    let min_key = xs
        .iter()
        .enumerate()
        .min_by_key(|(_, x)| x.abs())
        .map(|(i, _)| i);
    let max_by = xs
        .iter()
        .enumerate()
        .max_by(|a, b| (a.1 % 17).cmp(&(b.1 % 17)))
        .map(|(i, _)| i);
    let pos = xs.iter().position(|&x| x > 400);
    d.i64(product)
        .count(min_key.unwrap_or(n))
        .count(max_by.unwrap_or(n))
        .count(pos.unwrap_or(n));
    d.u8(u8::from(xs.contains(&0)))
        .u8(u8::from(xs.iter().all(|&x| x > -513)));

    let reduced = xs.iter().copied().reduce(|a, b| a.max(b) - (a.min(b) & 15));
    let counted = xs.iter().filter(|x| x.count_ones() % 2 == 1).count();
    let last = xs.iter().rev().skip(2).last();
    let nth = xs.iter().rev().nth(n / 3);
    d.i32(reduced.unwrap_or(0))
        .count(counted)
        .i32(*last.unwrap_or(&0))
        .i32(*nth.unwrap_or(&0));

    let (negative, nonnegative): (Vec<i32>, Vec<i32>) = xs.iter().partition(|x| **x < 0);
    let (idx, vals): (Vec<u16>, Vec<i32>) = xs
        .iter()
        .enumerate()
        .filter(|(_, x)| **x % 5 == 0)
        .map(|(i, x)| (i as u16, *x))
        .unzip();
    d.count(negative.len())
        .count(nonnegative.len())
        .count(idx.len());
    for (i, v) in idx.iter().zip(&vals) {
        d.u16(*i).i32(*v);
    }

    // Collecting into a `String`, a `BTreeMap`, and through `Result` and
    // `Option`, which stop at the first failure.
    let s: String = xs
        .iter()
        .take(12)
        .map(|&x| char::from(b'a' + (x.rem_euclid(26)) as u8))
        .collect();
    d.str(&s);
    let buckets: BTreeMap<i32, u32> = xs.iter().fold(BTreeMap::new(), |mut m, &x| {
        *m.entry(x.div_euclid(128)).or_insert(0) += 1;
        m
    });
    for (k, v) in &buckets {
        d.i32(*k).u32(*v);
    }
    let parsed: Result<Vec<u8>, _> = text.split(' ').take(6).map(|w| w.parse::<u8>()).collect();
    d.u8(u8::from(parsed.is_ok()));
    let words: Result<Vec<u32>, _> = ["12", "7", "300", "0"]
        .iter()
        .map(|w| w.parse::<u32>())
        .collect();
    d.u32(words.map_or(0, |w| w.iter().sum()));
    let all_small: Option<Vec<u8>> = xs.iter().map(|&x| u8::try_from(x + 512).ok()).collect();
    let some_small: Option<Vec<u8>> = xs
        .iter()
        .take(3)
        .map(|&x| u8::try_from(x & 0xff).ok())
        .collect();
    d.u8(u8::from(all_small.is_some()))
        .count(some_small.map_or(99, |v| v.len()));

    // The constructors: `successors`, `repeat_with`, and an array by value.
    let collatz: Vec<u32> = core::iter::successors(Some(3 + cx.rng().below(24) as u32), |&x| {
        (x != 1).then(|| if x % 2 == 0 { x / 2 } else { 3 * x + 1 })
    })
    .collect();
    d.count(collatz.len())
        .u32(*collatz.iter().max().unwrap_or(&0));
    let mut state = 1u32;
    let squares: Vec<u32> = core::iter::repeat_with(|| {
        state = state.wrapping_mul(0x2c1b_3c6d).wrapping_add(0x297a_2d39);
        state >> 16
    })
    .take(8)
    .collect();
    for q in squares {
        d.u32(q);
    }
    let array = [xs[0], xs[1], xs[2], xs[n - 1]];
    let mut from_array = array.into_iter();
    let back = from_array.next_back();
    d.i32(back.unwrap_or(0))
        .i32(from_array.map(|x| x * 2).sum());
    cx.digest(TAG_ITERATORS, &d);
}

// ---------------------------------------------------------------------------
// The expression tree
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum Expr {
    Num(i64),
    Neg(Box<Expr>),
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
    Div(Box<Expr>, Box<Expr>),
    Rem(Box<Expr>, Box<Expr>),
}

/// Why an expression has no value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EvalError {
    Overflow,
    DivideByZero,
}

impl Expr {
    fn eval(&self) -> Result<i64, EvalError> {
        use EvalError::{DivideByZero, Overflow};
        let pair = |a: &Expr, b: &Expr| Ok::<_, EvalError>((a.eval()?, b.eval()?));
        match self {
            Expr::Num(n) => Ok(*n),
            Expr::Neg(e) => e.eval()?.checked_neg().ok_or(Overflow),
            Expr::Add(a, b) => pair(a, b).and_then(|(x, y)| x.checked_add(y).ok_or(Overflow)),
            Expr::Sub(a, b) => pair(a, b).and_then(|(x, y)| x.checked_sub(y).ok_or(Overflow)),
            Expr::Mul(a, b) => pair(a, b).and_then(|(x, y)| x.checked_mul(y).ok_or(Overflow)),
            Expr::Div(a, b) | Expr::Rem(a, b) => {
                let (x, y) = pair(a, b)?;
                if y == 0 {
                    return Err(DivideByZero);
                }
                let r = if matches!(self, Expr::Div(..)) {
                    x.checked_div(y)
                } else {
                    x.checked_rem(y)
                };
                r.ok_or(Overflow)
            }
        }
    }

    /// Node count and height, by recursion over the boxes.
    fn shape(&self) -> (u32, u32) {
        match self {
            Expr::Num(_) => (1, 1),
            Expr::Neg(e) => {
                let (n, h) = e.shape();
                (n + 1, h + 1)
            }
            Expr::Add(a, b)
            | Expr::Sub(a, b)
            | Expr::Mul(a, b)
            | Expr::Div(a, b)
            | Expr::Rem(a, b) => {
                let ((na, ha), (nb, hb)) = (a.shape(), b.shape());
                (na + nb + 1, ha.max(hb) + 1)
            }
        }
    }
}

/// Fully parenthesized, so the parser's precedence cannot change the value.
impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (a, op, b) = match self {
            Expr::Num(n) => return write!(f, "{n}"),
            Expr::Neg(e) => return write!(f, "-{e}"),
            Expr::Add(a, b) => (a, '+', b),
            Expr::Sub(a, b) => (a, '-', b),
            Expr::Mul(a, b) => (a, '*', b),
            Expr::Div(a, b) => (a, '/', b),
            Expr::Rem(a, b) => (a, '%', b),
        };
        write!(f, "({a} {op} {b})")
    }
}

fn gen_expr(rng: &mut Rng, depth: u32) -> Expr {
    if depth == 0 || rng.chance(1, 5) {
        // Mostly small, sometimes near 2^40, so products overflow sometimes.
        let n = if rng.chance(1, 6) {
            (rng.next_u64() >> 24) as i64
        } else {
            rng.below(40) as i64
        };
        return Expr::Num(n);
    }
    let a = Box::new(gen_expr(rng, depth - 1));
    match rng.below(7) {
        0 => Expr::Neg(a),
        k => {
            let b = Box::new(gen_expr(rng, depth - 1));
            match k {
                1 | 2 => Expr::Add(a, b),
                3 => Expr::Sub(a, b),
                4 => Expr::Mul(a, b),
                5 => Expr::Div(a, b),
                _ => Expr::Rem(a, b),
            }
        }
    }
}

fn eval_code(r: Result<i64, EvalError>) -> i64 {
    match r {
        Ok(v) => v,
        Err(EvalError::Overflow) => i64::MIN,
        Err(EvalError::DivideByZero) => i64::MIN + 1,
    }
}

fn expr_tree(cx: &mut Ctx) {
    let mut d = Digest::new();
    let trees = 2 + cx.scale() / 2;
    let mut values = Vec::new();
    for _ in 0..trees {
        let depth = 1 + cx.rng().below(3) as u32;
        let e = gen_expr(cx.rng(), depth);
        let (nodes, height) = e.shape();
        let value = e.eval();
        d.u32(nodes).u32(height).i64(eval_code(value));
        // A clone is a deep copy of every box, and equal to the original.
        let copy = e.clone();
        d.u8(u8::from(copy == e));
        if let Expr::Add(a, _) | Expr::Mul(a, _) = &copy {
            d.i64(eval_code(a.eval()));
        }
        values.push(value);
    }
    let ok = values.iter().filter(|v| v.is_ok()).count();
    d.count(ok);
    cx.digest(TAG_EXPR_TREE, &d);

    if cx.fault(FAULT_FORMATTED) {
        let (i, v) = values
            .iter()
            .enumerate()
            .find_map(|(i, v)| v.ok().map(|v| (i, v)))
            .unwrap_or((trees as usize, 0));
        let wanted = black_box(v) ^ 1;
        if v != wanted {
            panic!("tree {i} of {trees} evaluated to {v}, and the check wanted {wanted:#x}");
        }
    }
}

// ---------------------------------------------------------------------------
// The parser, and memoized mutual recursion
// ---------------------------------------------------------------------------

/// Why text is not an expression; positions are byte offsets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParseError {
    Unexpected(char, u32),
    End,
    Trailing(u32),
    TooLarge(u32),
    TooDeep,
}

/// Recursive descent over `expr := term (('+'|'-') term)*`,
/// `term := unary (('*'|'/'|'%') unary)*`, `unary := '-' unary | atom`,
/// `atom := digits | '(' expr ')'`: `expr`, `term`, `unary` and `atom` are
/// mutually recursive.
struct Parser<'s> {
    text: &'s str,
    at: usize,
    depth: u32,
}

impl Parser<'_> {
    /// The next character after ASCII spaces. Not `trim_start`, whose Unicode
    /// whitespace tables cost the guest more than the rest of the parser.
    fn peek(&mut self) -> Option<char> {
        while self.text.as_bytes().get(self.at) == Some(&b' ') {
            self.at += 1;
        }
        self.text[self.at..].chars().next()
    }

    fn bump(&mut self, c: char) {
        self.at += c.len_utf8();
    }

    fn expr(&mut self) -> Result<Expr, ParseError> {
        self.depth += 1;
        if self.depth > 24 {
            return Err(ParseError::TooDeep);
        }
        let mut lhs = self.term()?;
        while let Some(c @ ('+' | '-')) = self.peek() {
            self.bump(c);
            let rhs = Box::new(self.term()?);
            lhs = if c == '+' {
                Expr::Add(Box::new(lhs), rhs)
            } else {
                Expr::Sub(Box::new(lhs), rhs)
            };
        }
        self.depth -= 1;
        Ok(lhs)
    }

    fn term(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.unary()?;
        loop {
            let make: fn(Box<Expr>, Box<Expr>) -> Expr = match self.peek() {
                Some('*') => Expr::Mul,
                Some('/') => Expr::Div,
                Some('%') => Expr::Rem,
                _ => return Ok(lhs),
            };
            self.bump('*');
            lhs = make(Box::new(lhs), Box::new(self.unary()?));
        }
    }

    fn unary(&mut self) -> Result<Expr, ParseError> {
        match self.peek() {
            Some('-') => {
                self.bump('-');
                Ok(Expr::Neg(Box::new(self.unary()?)))
            }
            _ => self.atom(),
        }
    }

    fn atom(&mut self) -> Result<Expr, ParseError> {
        let start = self.at as u32;
        match self.peek() {
            Some('(') => {
                self.bump('(');
                let e = self.expr()?;
                match self.peek() {
                    Some(')') => {
                        self.bump(')');
                        Ok(e)
                    }
                    Some(c) => Err(ParseError::Unexpected(c, self.at as u32)),
                    None => Err(ParseError::End),
                }
            }
            Some('0'..='9') => {
                let digits = self.text[self.at..]
                    .bytes()
                    .take_while(u8::is_ascii_digit)
                    .count();
                let lexeme = &self.text[self.at..self.at + digits];
                self.at += digits;
                lexeme
                    .parse::<i64>()
                    .map(Expr::Num)
                    .map_err(|_| ParseError::TooLarge(start))
            }
            Some(c) => Err(ParseError::Unexpected(c, self.at as u32)),
            None => Err(ParseError::End),
        }
    }
}

fn parse(text: &str) -> Result<Expr, ParseError> {
    let mut p = Parser {
        text,
        at: 0,
        depth: 0,
    };
    let e = p.expr()?;
    match p.peek() {
        None => Ok(e),
        Some(_) => Err(ParseError::Trailing(p.at as u32)),
    }
}

/// Unparenthesized text from tokens, with the precedence the parser must get
/// right and some errors it must report.
fn gen_text(rng: &mut Rng) -> String {
    const OPS: [&str; 6] = [" + ", "-", " * ", "/", " % ", " - "];
    let mut s = String::new();
    let terms = 2 + rng.below(6);
    let mut open = 0u32;
    for i in 0..terms {
        if rng.chance(1, 4) {
            s.push('(');
            open += 1;
        }
        if rng.chance(1, 8) {
            s.push('-');
        }
        // Digit by digit, leading zeros included: `to_string` would cost
        // more than parsing the result.
        for _ in 0..1 + rng.below(3) {
            s.push(char::from(b'0' + rng.below(10) as u8));
        }
        if open > 0 && rng.chance(1, 3) {
            s.push(')');
            open -= 1;
        }
        if i + 1 < terms {
            s.push_str(OPS[rng.index(OPS.len())]);
        }
    }
    // Usually balanced; one in six keeps an open parenthesis or adds a stray
    // character, so the error paths run.
    match rng.below(6) {
        0 => s.push_str(" $"),
        1 => {}
        _ => (0..open).for_each(|_| s.push(')')),
    }
    s
}

fn parse_code(r: &Result<Expr, ParseError>) -> Digest {
    let mut d = Digest::new();
    match r {
        Ok(e) => d.u8(0).i64(eval_code(e.eval())),
        Err(ParseError::Unexpected(c, at)) => d.u8(1).u32(*c as u32).u32(*at),
        Err(ParseError::End) => d.u8(2),
        Err(ParseError::Trailing(at)) => d.u8(3).u32(*at),
        Err(ParseError::TooLarge(at)) => d.u8(4).u32(*at),
        Err(ParseError::TooDeep) => d.u8(5),
    };
    d
}

/// Hofstadter's female and male sequences, mutually recursive, memoized in
/// one map keyed by which sequence and where.
fn female(n: u32, memo: &mut BTreeMap<(bool, u32), u32>) -> u32 {
    if n == 0 {
        return 1;
    }
    if let Some(&v) = memo.get(&(true, n)) {
        return v;
    }
    let f = female(n - 1, memo);
    let v = n - male(f, memo);
    memo.insert((true, n), v);
    v
}

fn male(n: u32, memo: &mut BTreeMap<(bool, u32), u32>) -> u32 {
    if n == 0 {
        return 0;
    }
    if let Some(&v) = memo.get(&(false, n)) {
        return v;
    }
    let m = male(n - 1, memo);
    let v = n - female(m, memo);
    memo.insert((false, n), v);
    v
}

fn parser(cx: &mut Ctx) {
    let mut d = Digest::new();

    // Round trip: a generated tree, printed and parsed back, is the same tree.
    let depth = 2 + cx.scale() / 8;
    for _ in 0..1 + cx.scale() / 4 {
        let e = gen_expr(cx.rng(), depth);
        let text = format!("{e}");
        let back = parse(&text);
        d.u8(u8::from(back.as_ref() == Ok(&e))).count(text.len());
        d.u64(parse_code(&back).finish());
    }
    for _ in 0..1 + cx.scale() / 2 {
        let text = gen_text(cx.rng());
        d.str(&text).u64(parse_code(&parse(&text)).finish());
    }
    let payload = String::from_utf8_lossy(prefix(cx.payload(), 48));
    d.u64(parse_code(&parse(&payload)).finish());
    d.u64(parse_code(&parse(&"(".repeat(26))).finish());

    let mut memo = BTreeMap::new();
    let n = 3 + cx.rng().below(3) as u32 + 3 * cx.scale();
    let f: Vec<u32> = (0..n).map(|i| female(i, &mut memo)).collect();
    let m: Vec<u32> = (0..n).map(|i| male(i, &mut memo)).collect();
    d.count(memo.len());
    for (a, b) in f.iter().zip(&m) {
        d.u32(*a).u32(*b);
    }
    cx.digest(TAG_PARSER, &d);

    if cx.fault(FAULT_EXPECT) {
        // One past the largest index the recursion reached: never memoized.
        let probe = black_box(n + f[f.len() - 1]);
        let v = memo
            .get(&(true, probe))
            .copied()
            .expect("the memo holds every female value the recursion reached");
        d.u32(v);
    }
}

// ---------------------------------------------------------------------------
// Deep recursion
// ---------------------------------------------------------------------------

/// Not a tail call: the result of the recursion is used after it returns, so
/// every level is a live frame at the bottom.
fn chain(n: u32, x: u32) -> u32 {
    if n == 0 {
        return x;
    }
    let below = chain(n - 1, x.wrapping_mul(0x9e37_79b9).wrapping_add(n));
    below.rotate_left(n % 32) ^ n
}

struct Link {
    value: u32,
    next: Option<Box<Link>>,
}

/// The list's length and a fingerprint, recursively.
fn walk_list(link: &Option<Box<Link>>) -> (u32, u32) {
    match link {
        None => (0, 0),
        Some(l) => {
            let (n, h) = walk_list(&l.next);
            (n + 1, h.rotate_left(5) ^ l.value)
        }
    }
}

fn deep(cx: &mut Ctx) {
    let mut d = Digest::new();
    let depth = 400 + 1225 * cx.scale();
    let seed = cx.rng().next_u32();
    d.u32(depth).u32(chain(depth, seed));

    // A list a sixteenth as long, walked recursively and dropped by the
    // compiler's drop glue, which recurses once per link. Shorter than the
    // recursion because every link is an allocation the guest never frees.
    let mut head: Option<Box<Link>> = None;
    for i in 0..depth / 16 {
        head = Some(Box::new(Link {
            value: seed.wrapping_add(i).rotate_right(i % 32),
            next: head,
        }));
    }
    let (n, h) = walk_list(&head);
    d.u32(n).u32(h);
    drop(head);
    cx.digest(TAG_DEEP, &d);
}

// ---------------------------------------------------------------------------
// Large values
// ---------------------------------------------------------------------------

/// Over half a kilobyte, moved by value: every pass, return, clone and swap is a
/// `memcpy`, and the derived `Ord` compares the byte rows with `memcmp`. The
/// key's `u128` and `i64` take the 32-bit target's multi-word compares.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Big {
    key: (u8, i16, u128, i64),
    words: [u64; 32],
    rows: [[u8; 32]; 8],
}

/// Values drawn from very few, so two `Big`s often tie on the key and on the
/// first word, and the comparison then walks all 32 words to the last one and
/// on into the rows.
fn gen_big(rng: &mut Rng) -> Big {
    let mut b = Big {
        key: (
            rng.below(2) as u8,
            rng.below(2) as i16 - 1,
            u128::from(rng.below(2)) << 100,
            -(rng.below(2) as i64),
        ),
        words: [0; 32],
        rows: [[0; 32]; 8],
    };
    let spread = rng.below(3);
    b.words[0] = rng.below(spread + 1);
    b.words[31] = rng.below(spread + 1);
    for row in b.rows.iter_mut().skip(6) {
        for byte in row.iter_mut().skip(28) {
            *byte = rng.below(2) as u8;
        }
    }
    b
}

/// By value in, by value out.
fn stamp(mut b: Big, k: u64) -> Big {
    b.words[(k % 32) as usize] ^= k;
    b.rows[(k % 8) as usize][(k % 32) as usize] ^= 0x80;
    b
}

fn fold_big(d: &mut Digest, b: &Big) {
    d.u8(b.key.0).u16(b.key.1 as u16).u128(b.key.2).i64(b.key.3);
    let words = b.words.iter().fold(0u64, |h, w| h ^ w);
    // Whole-row compares, which are `bcmp`, and the bytes `gen_big` fills; a
    // byte-by-byte fold of all 256 would dominate the section, and `stamp`'s
    // flipped byte shows in the count, the compares and the sorted order.
    let nonzero = b.rows.iter().filter(|r| **r != [0; 32]).count();
    d.u64(words).count(nonzero);
    d.bytes(&b.rows[6][28..]).bytes(&b.rows[7][28..]);
}

fn large(cx: &mut Ctx) {
    let mut d = Digest::new();
    let count = 2 + cx.scale() as usize / 2;
    let mut bigs: Vec<Big> = (0..count).map(|_| gen_big(cx.rng())).collect();

    let first = bigs[0].clone();
    let stamped = stamp(first.clone(), cx.rng().next_u64());
    d.u8(u8::from(stamped == first))
        .u8(stamped.cmp(&first) as u8)
        .u8(u8::from(stamped.clone() == stamped));
    bigs.push(stamped);

    // The derived order, by a stable sort and an unstable one: every field
    // takes part, so they agree.
    let mut unstable = bigs.clone();
    bigs.sort();
    unstable.sort_unstable();
    d.u8(u8::from(bigs == unstable));
    for b in &bigs {
        fold_big(&mut d, b);
    }
    let ties = bigs.windows(2).filter(|w| w[0] == w[1]).count();
    d.count(ties);

    // Swaps and replacements move whole values in place.
    let last = bigs.len() - 1;
    bigs.swap(0, last);
    let (lo, hi) = bigs.split_at_mut(last);
    core::mem::swap(&mut lo[0], &mut hi[0]);
    let old = core::mem::replace(&mut bigs[1], stamp(first, 7));
    d.u8(old.cmp(&bigs[1]) as u8);
    d.u8(u8::from(bigs.iter().is_sorted()));
    let max = bigs.iter().max().map(|b| b.words[31]);
    d.u64(max.unwrap_or(u64::MAX));

    // Tuples of every width, sorted by their derived lexicographic order.
    type Widths = (u8, u16, u32, u64, i8, i128, bool, char);
    let mut tuples: Vec<Widths> = (0..6)
        .map(|_| {
            let r = cx.rng().next_u64();
            (
                (r % 3) as u8,
                (r >> 8) as u16 % 4,
                (r >> 16) as u32 % 5,
                r >> 40,
                (r >> 3) as i8,
                -i128::from(r) << 64,
                r & 1 == 1,
                char::from_u32(0x61 + (r % 5) as u32).unwrap_or('?'),
            )
        })
        .collect();
    tuples.sort_unstable();
    for t in &tuples {
        d.u8(t.0).u16(t.1).u32(t.2).u64(t.3).u8(t.4 as u8);
        d.i128(t.5).u8(u8::from(t.6)).u32(t.7 as u32);
    }

    // `Option<Box<Big>>` uses the box's non-null niche for `None`.
    let mut slot: Option<Box<Big>> = None;
    d.u8(u8::from(slot.is_none()));
    let boxed = slot.get_or_insert_with(|| Box::new(gen_big(&mut Rng::new(3))));
    boxed.words[5] = 55;
    let taken = slot.take();
    d.u64(taken.as_deref().map_or(0, |b| b.words[5]))
        .u8(u8::from(slot.is_none()));
    let unboxed: Option<Big> = taken.map(|b| *b);
    d.u8(unboxed.map_or(0, |b| b.key.0 + 1));
    cx.digest(TAG_LARGE, &d);
}

// ---------------------------------------------------------------------------
// Shared ownership
// ---------------------------------------------------------------------------

/// A tree node owned by its parent and pointing back at it weakly, so the
/// tree drops when its root does.
struct Node {
    id: u32,
    value: i64,
    children: Vec<Rc<RefCell<Node>>>,
    parent: Weak<RefCell<Node>>,
}

fn new_node(id: u32, value: i64, parent: &Weak<RefCell<Node>>) -> Rc<RefCell<Node>> {
    Rc::new(RefCell::new(Node {
        id,
        value,
        children: Vec::new(),
        parent: parent.clone(),
    }))
}

/// A subtree's sum, recursively, counting visits in a `Cell` it only reads
/// through `&`.
fn subtree(node: &Rc<RefCell<Node>>, visits: &Cell<u32>) -> i64 {
    visits.set(visits.get() + 1);
    let n = node.borrow();
    n.value + n.children.iter().map(|c| subtree(c, visits)).sum::<i64>()
}

/// Levels above `node`, by following `Weak` parents up.
fn depth_of(node: &Rc<RefCell<Node>>) -> u32 {
    let mut depth = 0;
    let mut up = node.borrow().parent.upgrade();
    while let Some(p) = up {
        depth += 1;
        up = p.borrow().parent.upgrade();
    }
    depth
}

fn shared(cx: &mut Ctx) {
    let mut d = Digest::new();
    let count = 4 + 6 * cx.scale();
    let root = new_node(0, 1, &Weak::new());
    let mut all = vec![root.clone()];
    for id in 1..count {
        let parent = all[cx.rng().index(all.len())].clone();
        let value = cx.rng().below(1000) as i64 - 500;
        let child = new_node(id, value, &Rc::downgrade(&parent));
        parent.borrow_mut().children.push(child.clone());
        all.push(child);
    }

    let visits = Cell::new(0);
    d.i64(subtree(&root, &visits)).u32(visits.get());
    // Each node is held by `all` and by its parent's `children`; the root by
    // `all` and `root`. Its weak count is its children's back-pointers.
    for node in all.iter().step_by(3) {
        d.count(Rc::strong_count(node))
            .count(Rc::weak_count(node))
            .u32(depth_of(node));
    }

    // Borrow states: a shared borrow refuses a mutable one and allows another
    // shared one; a mutable borrow refuses both.
    let probe = &all[cx.rng().index(all.len())];
    {
        let held = probe.borrow();
        d.u8(u8::from(probe.try_borrow_mut().is_err()))
            .u8(u8::from(probe.try_borrow().is_ok()))
            .u32(held.id);
    }
    {
        let mut held = probe.borrow_mut();
        held.value += 1;
        d.u8(u8::from(probe.try_borrow().is_err()))
            .u8(u8::from(probe.try_borrow_mut().is_err()));
    }
    d.u8(u8::from(probe.try_borrow_mut().is_ok()));

    // Detach a subtree from its parent: from here it lives only through `all`
    // and `v`, so the strong count drops by the parent's handle.
    let victim = all
        .iter()
        .find(|n| n.borrow().id != 0 && !n.borrow().children.is_empty())
        .cloned();
    if let Some(v) = victim {
        let parent = v.borrow().parent.upgrade();
        if let Some(p) = parent {
            p.borrow_mut().children.retain(|c| !Rc::ptr_eq(c, &v));
            d.count(Rc::strong_count(&v));
        }
        let under = Cell::new(0);
        d.i64(subtree(&v, &under)).u32(under.get());
    }
    let visits = Cell::new(0);
    d.i64(subtree(&root, &visits)).u32(visits.get());

    // Drop every handle but the root's: the attached tree stays alive through
    // the root, the detached subtree dies, and the weak references tell which.
    let weaks: Vec<Weak<RefCell<Node>>> = all.iter().map(Rc::downgrade).collect();
    drop(all);
    let alive = weaks.iter().filter(|w| w.upgrade().is_some()).count();
    d.count(alive).count(Rc::strong_count(&root));

    // A cell in a cell: `Cell::replace`, `Cell::take`, `RefCell::replace_with`.
    let cell = Cell::new(count);
    let old = cell.replace(old_plus(count));
    let taken = cell.take();
    let rc = RefCell::new(vec![1u32, 2, 3]);
    let prev = rc.replace_with(|v| v.iter().map(|x| x * count).collect());
    d.u32(old).u32(taken).u32(cell.get());
    d.u32(prev.iter().sum()).u32(rc.borrow().iter().sum());
    cx.digest(TAG_SHARED, &d);

    if cx.fault(FAULT_DOUBLE_BORROW) {
        // Hold the root mutably, then walk up from the deepest live node: the
        // walk reaches the root and borrows it again.
        let leaf = weaks
            .iter()
            .filter_map(Weak::upgrade)
            .max_by_key(depth_of)
            .unwrap_or_else(|| root.clone());
        let mut held = root.borrow_mut();
        held.value = black_box(held.value) + 1;
        d.u32(depth_of(&leaf));
    }
    drop(weaks);
    d.count(Rc::weak_count(&root));
}

fn old_plus(x: u32) -> u32 {
    x + 1
}

// ---------------------------------------------------------------------------
// Atomics
// ---------------------------------------------------------------------------

/// Counters behind an `Arc`, updated through `&self` only.
struct Counters {
    hits: AtomicU32,
    peak: AtomicUsize,
    bits: AtomicU32,
    owner: AtomicU32,
}

fn atomics(cx: &mut Ctx) {
    let mut d = Digest::new();
    let shared = Arc::new(Counters {
        hits: AtomicU32::new(0),
        peak: AtomicUsize::new(0),
        bits: AtomicU32::new(0),
        owner: AtomicU32::new(0),
    });
    let workers: Vec<Arc<Counters>> = (0..4).map(|_| Arc::clone(&shared)).collect();
    d.count(Arc::strong_count(&shared));

    let rounds = 8 + 16 * cx.scale();
    let order = AtomicOrdering::SeqCst;
    for r in 0..rounds {
        let w = &workers[r as usize % workers.len()];
        let v = cx.rng().next_u32();
        let before = w.hits.fetch_add(v >> 24, order);
        w.peak.fetch_max((v % 4096) as usize, order);
        w.bits.fetch_xor(v, order);
        w.bits.fetch_or(1 << (v % 32), order);
        w.bits.fetch_and(!(1 << ((v >> 5) % 32)), order);
        // A lock word: claimed only when free, released on odd rounds.
        let claim = w.owner.compare_exchange(0, r + 1, order, order);
        d.u32(before)
            .u32(claim.unwrap_or_else(|held| held + 0x1000));
        if r % 2 == 1 {
            d.u32(w.owner.swap(0, order));
        }
    }
    let prev = shared
        .hits
        .fetch_update(order, order, |h| h.checked_sub(7))
        .unwrap_or(u32::MAX);
    let min = shared.hits.fetch_min(1 << 20, order);
    let nand = shared.bits.fetch_nand(0x0f0f_0f0f, order);
    let sub = shared.hits.fetch_sub(1, order);
    let weak_cas = shared
        .owner
        .compare_exchange_weak(u32::MAX, 1, order, order)
        .unwrap_or_else(|v| v ^ 0xa5a5);
    d.u32(prev).u32(min).u32(nand).u32(sub).u32(weak_cas);
    d.u32(shared.hits.load(order))
        .count(shared.peak.load(order))
        .u32(shared.bits.load(order))
        .u32(shared.owner.load(order));

    // `Arc` bookkeeping: `try_unwrap` fails while clones exist, `get_mut`
    // likewise, and `make_mut` copies on write.
    drop(workers);
    d.count(Arc::strong_count(&shared));
    let alone = Arc::try_unwrap(shared).map(|c| c.hits.into_inner());
    d.u32(alone.unwrap_or(0));

    let mut data = Arc::new(vec![cx.rng().next_u32(); 4]);
    let other = Arc::clone(&data);
    d.u8(u8::from(Arc::get_mut(&mut data).is_none()));
    Arc::make_mut(&mut data)[0] ^= 1;
    d.u8(u8::from(Arc::ptr_eq(&data, &other)))
        .u32(data[0] ^ other[0])
        .count(Arc::strong_count(&other));
    let hits = AtomicUsize::new(3);
    d.count(hits.fetch_add(4, order)).count(hits.into_inner());
    cx.digest(TAG_ATOMICS, &d);
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A value that did not parse, and why. `Int` wraps core's own error, so the
/// chain crosses into `core`.
#[derive(Debug)]
enum FieldError {
    Int(core::num::ParseIntError),
    Range { value: i64, max: i64 },
    Missing,
}

/// A config that did not parse: the line, over the field's error.
#[derive(Debug)]
enum ConfigError {
    Utf8(core::str::Utf8Error),
    Line { line: u32, source: FieldError },
    Empty,
}

impl fmt::Display for FieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldError::Int(_) => f.write_str("not an integer"),
            FieldError::Range { value, max } => write!(f, "{value} is outside -{max}..={max}"),
            FieldError::Missing => f.write_str("no '=' in the line"),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Utf8(e) => write!(f, "not UTF-8 after {} bytes", e.valid_up_to()),
            ConfigError::Line { line, .. } => write!(f, "line {line}"),
            ConfigError::Empty => f.write_str("no settings"),
        }
    }
}

impl core::error::Error for FieldError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            FieldError::Int(e) => Some(e),
            _ => None,
        }
    }
}

impl core::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            ConfigError::Line { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<core::num::ParseIntError> for FieldError {
    fn from(e: core::num::ParseIntError) -> FieldError {
        FieldError::Int(e)
    }
}

impl From<core::str::Utf8Error> for ConfigError {
    fn from(e: core::str::Utf8Error) -> ConfigError {
        ConfigError::Utf8(e)
    }
}

/// `key=value` with `value` at most 10_000 either side of zero, so no payload
/// can make the sum in [`load`] overflow. `unsigned_abs`, because `abs` of
/// `i64::MIN` is itself an overflow.
fn parse_field(line: &str) -> Result<(&str, i64), FieldError> {
    let (key, value) = line.split_once('=').ok_or(FieldError::Missing)?;
    let value: i64 = value.trim().parse()?;
    if value.unsigned_abs() > 10_000 {
        return Err(FieldError::Range { value, max: 10_000 });
    }
    Ok((key.trim(), value))
}

fn parse_config(bytes: &[u8]) -> Result<BTreeMap<String, i64>, ConfigError> {
    let text = core::str::from_utf8(bytes)?;
    let mut settings = BTreeMap::new();
    for (i, line) in text.lines().enumerate().filter(|(_, l)| !l.is_empty()) {
        let (key, value) = parse_field(line).map_err(|source| ConfigError::Line {
            line: i as u32 + 1,
            source,
        })?;
        settings.insert(key.to_string(), value);
    }
    if settings.is_empty() {
        return Err(ConfigError::Empty);
    }
    Ok(settings)
}

/// The top layer: any error, boxed, including one made from a `&str`.
fn load(bytes: &[u8]) -> Result<i64, Box<dyn core::error::Error>> {
    let settings = parse_config(bytes)?;
    let total: i64 = settings.values().sum();
    if total < 0 {
        return Err("the settings sum below zero".into());
    }
    let width = u8::try_from(settings.len())?;
    Ok(total * i64::from(width))
}

/// The error and its sources, outermost first, joined by `": "`.
fn chain_text(e: &dyn core::error::Error) -> String {
    let mut text = format!("{e}");
    let mut cause = e.source();
    while let Some(c) = cause {
        text.push_str(": ");
        text.push_str(&format!("{c}"));
        cause = c.source();
    }
    text
}

fn gen_config(rng: &mut Rng) -> Vec<u8> {
    let mut s = String::new();
    for i in 0..1 + rng.below(3) {
        let value = rng.below(12_000) as i64 - 500;
        match rng.below(12) {
            0 => s.push_str("no equals sign"),
            1 => s.push_str(&format!("k{i} = {value}x")),
            2 => s.push_str(&format!("k{i} = 99999999999999999999")),
            _ => s.push_str(&format!("k{i} = {value}")),
        }
        s.push('\n');
    }
    let mut bytes = s.into_bytes();
    if rng.chance(1, 10) {
        bytes.push(0xff);
    }
    bytes
}

fn errors(cx: &mut Ctx) {
    let mut d = Digest::new();
    let mut shown = String::new();
    let configs = 1 + cx.scale() / 2;
    for k in 0..=configs {
        // The last config is the payload itself, whatever it holds.
        let bytes = if k == configs {
            prefix(cx.payload(), 256).to_vec()
        } else {
            gen_config(cx.rng())
        };
        match load(&bytes) {
            Ok(v) => {
                d.u8(0).i64(v);
            }
            Err(e) => {
                let text = chain_text(e.as_ref());
                let typed = e.downcast_ref::<ConfigError>().is_some();
                d.u8(1).u8(u8::from(typed)).str(&text);
                if k % 3 == 0 || k == configs {
                    shown.push_str(&text);
                    shown.push('\n');
                }
            }
        }
    }

    // The combinators, over values the rng chooses.
    let a: Option<u32> = cx.rng().chance(2, 3).then(|| cx.rng().next_u32() >> 8);
    let b: Result<u32, &str> = if cx.rng().chance(1, 2) {
        Ok(cx.rng().below(100) as u32)
    } else {
        Err("b failed")
    };
    let c = b
        .map_err(|e| e.len())
        .and_then(|v| v.checked_sub(50).ok_or(99))
        .or_else(|e| if e == 99 { Ok(0) } else { Err(e) });
    let nested: Option<Result<u32, u8>> = a.map(|v| if v % 2 == 0 { Ok(v) } else { Err(1) });
    let transposed: Result<Option<u32>, u8> = nested.transpose();
    let flat = Some(a).flatten();
    let zipped = a.zip(b.ok());
    d.u32(c.unwrap_or_else(|e| e as u32 + 1000))
        .u32(transposed.map_or(2, |o| o.map_or(3, |v| v & 0xffff)))
        .u32(flat.unwrap_or_default())
        .u32(zipped.map_or(4, |(x, y)| x ^ y))
        .u32(a.ok_or("none").map_or(5, |v| v >> 4))
        .u8(u8::from(a.is_some_and(|v| v > 1 << 20)))
        .u32(a.xor(b.ok()).unwrap_or(6))
        .u32(a.filter(|v| v % 3 == 0).unwrap_or(7));
    cx.digest(TAG_ERRORS, &d);
    cx.section(TAG_ERROR_TEXT, shown.as_bytes());
}
