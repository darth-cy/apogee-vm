//! Allocation patterns: what a program computes must not depend on the heap
//! underneath it.
//!
//! On the host the heap is the system allocator, which reuses freed blocks; on
//! the guest it is guest-sdk's bump allocator, which never frees and rounds
//! every block up to its own alignment. A program whose output depended on
//! either — a block handed out twice, a realloc that dropped a tail, an
//! over-aligned type placed on a byte boundary, a `Vec` whose growth copied
//! the wrong prefix — would differ here. So each section allocates in one
//! pattern, reads everything back only *after* the pattern is done (a later
//! block written over an earlier one then shows), and emits a short readable
//! summary with a fingerprint of the contents.
//!
//! The guest never frees, so every growth, clone and `format!` below counts
//! against the run's total; the sizes are chosen so that total stays under
//! 4 MiB at [`crate::MAX_SCALE`], where this workload measures about 140 KiB
//! and the whole guest about 550 KiB.
//!
//! Capacities are emitted where they are Rust's to choose (`with_capacity`,
//! the amortized growth policy, `shrink_to`), because `Vec` takes the capacity
//! it asked for whatever the allocator returns, so they are the same on every
//! target. The one capacity that is not — a zero-sized type's, `usize::MAX` —
//! is only ever compared.
//!
//! Two things here are sized by what the guest's `opt-level = 0` build costs,
//! and both are worth knowing before porting code into a proof: `Digest` takes
//! a byte at a time, which is about 70 guest instructions per byte, so bulk
//! values go through [`Fold`] first; and dropping a `Vec` runs the slice drop
//! glue once per element even when the element needs no drop, so dropping a
//! million-element `Vec<()>` — which never allocated — costs eight million
//! instructions.

use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque};
use alloc::format;
use alloc::rc::{Rc, Weak};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::cell::RefCell;
use core::cmp::Reverse;
use core::fmt::Write;
use core::hint::black_box;
use core::mem;

use crate::{Ctx, Digest, Fault, Rng};

pub const TAGS: (u8, u8) = (0x70, 0x7f);

const TAG_SMALL_BOXES: u8 = 0x70;
const TAG_GROWTH: u8 = 0x71;
const TAG_RESERVE: u8 = 0x72;
const TAG_COLLECT: u8 = 0x73;
const TAG_ALIGN_ZST: u8 = 0x74;
const TAG_DEQUE: u8 = 0x75;
const TAG_BTREE: u8 = 0x76;
const TAG_HEAP: u8 = 0x77;
const TAG_MOVES: u8 = 0x78;
const TAG_COW: u8 = 0x79;
const TAG_RC: u8 = 0x7a;
const TAG_ANY: u8 = 0x7b;
const TAG_ARENA: u8 = 0x7c;
const TAG_CLONE: u8 = 0x7d;

const FAULT_WITH_CAPACITY: u8 = 0x70;
const FAULT_RESERVE: u8 = 0x71;
const FAULT_DOWNCAST: u8 = 0x72;
const FAULT_BORROW: u8 = 0x73;

pub const FAULTS: &[Fault] = &[
    Fault {
        code: FAULT_WITH_CAPACITY,
        what: "`Vec::<u64>::with_capacity` of a count whose byte size passes `isize::MAX` on \
               both widths: 'capacity overflow', raised before anything is allocated",
    },
    Fault {
        code: FAULT_RESERVE,
        what: "`reserve` on a non-empty `Vec` of exactly one more than `usize::MAX - len`: \
               'capacity overflow'",
    },
    Fault {
        code: FAULT_DOWNCAST,
        what: "`Box<dyn Any>::downcast` to the wrong type, unwrapped: 'called `Result::unwrap()` \
               on an `Err` value: Any { .. }'",
    },
    Fault {
        code: FAULT_BORROW,
        what: "`RefCell::borrow` of a tree node while a `borrow_mut` of it is held",
    },
];

pub fn run(cx: &mut Ctx) {
    small_boxes(cx);
    growth(cx);
    reserve(cx);
    collect(cx);
    align_and_zst(cx);
    deque(cx);
    btree(cx);
    heap(cx);
    moves(cx);
    cow(cx);
    rc(cx);
    any(cx);
    arena(cx);
    deep_clone(cx);
}

/// A word-at-a-time fold, feeding [`Digest`] once per section.
///
/// `Digest` takes a byte at a time, which the guest's `opt-level = 0` build
/// pays about 70 instructions for; a section that fingerprints thousands of
/// values would spend its whole budget there. This mixes a `u64` at a time out
/// of `wrapping_mul` and `rotate_left`, which are `#[inline(always)]` and so
/// are real instructions even at `opt-level = 0`, and the section emits
/// `Digest` of the one result. Every operation is fixed-width, so the answer
/// is the same on a 64-bit host as on the 32-bit guest.
#[derive(Clone, Copy)]
struct Fold(u64);

impl Fold {
    const fn new() -> Fold {
        Fold(0x243f_6a88_85a3_08d3)
    }

    fn word(&mut self, x: u64) -> &mut Fold {
        self.0 = (self.0 ^ x)
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .rotate_left(29);
        self
    }

    /// A `usize` that is the same number on every target — a length, an index.
    fn count(&mut self, n: usize) -> &mut Fold {
        self.word(n as u64)
    }

    /// Length-prefixed, so `("ab", "c")` and `("a", "bc")` differ.
    fn bytes(&mut self, bytes: &[u8]) -> &mut Fold {
        self.count(bytes.len());
        for chunk in bytes.chunks(8) {
            let mut word = [0u8; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            self.word(u64::from_le_bytes(word));
        }
        self
    }

    fn str(&mut self, s: &str) -> &mut Fold {
        self.bytes(s.as_bytes())
    }

    fn done(&self) -> u64 {
        self.0
    }
}

/// A section as `summary fingerprint`: the summary says what a mismatch is
/// about, the fingerprint covers what a summary cannot.
fn emit(cx: &mut Ctx, tag: u8, summary: &str, fold: &Fold) {
    let mut digest = Digest::new();
    digest.u64(fold.done());
    let body = format!("{summary} {:016x}", digest.finish());
    cx.section(tag, body.as_bytes());
}

/// `0..=MAX_SCALE` as a `usize`, for sizing loops.
fn scale(cx: &Ctx) -> usize {
    cx.scale() as usize
}

// ---------------------------------------------------------------------------
// (a) Many small blocks
// ---------------------------------------------------------------------------

/// Hundreds of blocks of mixed sizes and alignments, interleaved so that on
/// the bump allocator every block is padded up from its neighbour's end. Each
/// is written once as it is made and read back only when all exist, so a block
/// handed out twice shows as a changed fingerprint.
// The boxing inside the `Vec`s is the point: one block per element.
#[allow(clippy::vec_box)]
fn small_boxes(cx: &mut Ctx) {
    let n = 4 + 8 * scale(cx);
    let mut bytes: Vec<Box<u8>> = Vec::new();
    let mut words: Vec<Box<u64>> = Vec::new();
    let mut wides: Vec<Box<u128>> = Vec::new();
    let mut slices: Vec<Box<[u16]>> = Vec::new();
    let mut names: Vec<Box<str>> = Vec::new();
    for i in 0..n {
        let r = cx.rng().next_u64();
        bytes.push(Box::new(r as u8));
        wides.push(Box::new(u128::from(r) << (r % 64)));
        words.push(Box::new(r ^ i as u64));
        let len = (r >> 61) as usize;
        let slice: Vec<u16> = (0..len).map(|k| (r >> (k * 3)) as u16).collect();
        slices.push(slice.into_boxed_slice());
        // Excess capacity, so `into_boxed_str` has to shrink the block.
        let mut name = String::with_capacity(len + 8);
        for k in 0..len {
            name.push(char::from(b'a' + ((r >> (4 * k)) & 15) as u8));
        }
        names.push(name.into_boxed_str());
    }

    // Many one-word blocks, the smallest thing a heap is asked for.
    let singles: Vec<Box<u32>> = (0..12 + 24 * scale(cx))
        .map(|i| Box::new((i as u32).wrapping_mul(0x9e37_79b9)))
        .collect();

    // 1000-byte blocks, written sparsely: writing or folding all of one costs
    // more than the rest of this section at opt-level 0.
    let pages = 1 + scale(cx) / 4;
    let mut blocks: Vec<Box<[u8; 1000]>> = Vec::with_capacity(pages);
    for p in 0..pages {
        let mut block = Box::new([0u8; 1000]);
        let r = cx.rng().next_u64();
        for k in (p % 7..1000).step_by(199) {
            block[k] = (r >> (k % 56)) as u8;
        }
        blocks.push(block);
    }

    // Boxed slices and strs by every route in and out.
    let from_slice: Box<[u32]> = Box::from(&[3u32, 1, 4, 1, 5][..]);
    let mut back: Vec<u32> = from_slice.clone().into_vec();
    back.push(9);
    let from_str: Box<str> = Box::from("boxed");
    let mut string = from_str.clone().into_string();
    string.push_str("-grown");
    let empty: Box<[u64]> = Vec::new().into_boxed_slice();

    let mut f = Fold::new();
    for (i, ((b, w), x)) in bytes.iter().zip(&words).zip(&wides).enumerate().rev() {
        f.word(u64::from(**b)).word(**w);
        f.word(**x as u64).word((**x >> 64) as u64).count(i);
    }
    for (s, name) in slices.iter().zip(&names).rev() {
        f.str(name).count(s.len());
        for v in s.iter() {
            f.word(u64::from(*v));
        }
    }
    for x in singles.iter().rev() {
        f.word(u64::from(**x));
    }
    for (p, block) in blocks.iter().enumerate() {
        for k in (p % 7..1000).step_by(199) {
            f.word(u64::from(block[k]));
        }
        f.word(u64::from(block[999]));
    }
    for x in back.iter().chain(from_slice.iter()) {
        f.word(u64::from(*x));
    }
    f.str(&string).str(&from_str).count(empty.len());

    let summary = format!(
        "{n} each of u8 u64 u128 [u16] str, {} u32, {pages} pages, {string} {}",
        singles.len(),
        back.len()
    );
    emit(cx, TAG_SMALL_BOXES, &summary, &f);
}

// ---------------------------------------------------------------------------
// (b) Growth
// ---------------------------------------------------------------------------

/// `Vec`s grown one push at a time — every growth a reallocation that must
/// carry the old prefix over — then reshaped by every method that moves
/// elements within or between blocks.
fn growth(cx: &mut Ctx) {
    let n = 16 + 16 * scale(cx);
    let mut f = Fold::new();

    let mut v: Vec<u32> = Vec::new();
    let mut regrowths = 0u32;
    let mut cap = v.capacity();
    for _ in 0..n {
        v.push(cx.rng().next_u32());
        if v.capacity() != cap {
            regrowths += 1;
            cap = v.capacity();
        }
    }

    // Wider elements, whose growth policy starts from a different minimum.
    let mut rows: Vec<[u8; 24]> = Vec::new();
    let mut strings: Vec<String> = Vec::new();
    for i in 0..n / 4 {
        let r = cx.rng().next_u64();
        let mut row = [i as u8; 24];
        row[(r % 24) as usize] = (r >> 8) as u8;
        rows.push(row);
        let mut s = String::new();
        for k in 0..r % 6 {
            s.push(char::from(b'k' + k as u8));
        }
        strings.push(s);
    }

    v.insert(0, 7);
    let mid = v.len() / 2;
    v.insert(mid, 9);
    let removed = v.remove(3);
    let swapped = v.swap_remove(1);
    // The length is exactly `n >= 16` until the data-dependent `retain`, so
    // every fixed range here is in bounds whatever the seed.
    let drained: Vec<u32> = v.drain(2..10).collect();
    let spliced: Vec<u32> = v.splice(1..3, drained.iter().rev().copied()).collect();
    let mut tail = v.split_off(v.len() / 2);
    v.extend_from_within(..5);
    let third = v.len() / 3;
    v.rotate_left(third);
    v.append(&mut tail);
    v.retain(|x| x % 5 != 0);
    v.dedup_by_key(|x| *x >> 29);
    v.truncate(v.len() - v.len() / 8);
    let before_sort = v.clone();
    v.sort_unstable();
    let last = rows.len() - 1;
    rows.swap(0, last);
    rows.reverse();
    strings.retain(|s| !s.is_empty());

    for x in before_sort.iter().chain(&v).chain(&spliced) {
        f.word(u64::from(*x));
    }
    for row in &rows {
        f.bytes(row);
    }
    for s in &strings {
        f.str(s);
    }
    f.word(u64::from(removed)).word(u64::from(swapped));
    f.count(tail.len());

    let summary = format!(
        "{n} pushes, {regrowths} regrowths, len {} after reshaping, {} rows, {} strings",
        v.len(),
        rows.len(),
        strings.len()
    );
    emit(cx, TAG_GROWTH, &summary, &f);
}

/// The capacity API, answered in words. Every capacity printed is one `Vec`
/// chose for itself from a request, the same on every target; the `Err`s are
/// the requests no target can grant, refused before anything is allocated.
///
/// The lines are written a few values at a time: `write!` costs the guest
/// thousands of instructions per call at opt-level 0.
fn reserve(cx: &mut Ctx) {
    let k = 1 + cx.rng().index(40);
    let mut text = String::new();

    let mut v: Vec<u64> = Vec::with_capacity(k);
    let asked = v.capacity();
    v.extend((0..k as u64).map(|x| x * x));
    let filled = v.capacity();
    v.push(1);
    let grown = v.capacity();
    v.reserve(3 * k);
    let reserved = v.capacity() >= v.len() + 3 * k;
    v.reserve_exact(10 * k);
    let exact = v.capacity();
    v.shrink_to(k + 2);
    let shrunk = v.capacity();
    v.truncate(k / 2);
    v.shrink_to_fit();
    let _ = write!(
        text,
        "with_capacity({k}) {asked}, filled {filled}, one more {grown}, reserve {reserved}, \
         reserve_exact {exact}, shrink_to {shrunk}, shrink_to_fit {} of {}",
        v.capacity(),
        v.len()
    );

    let ok = v.try_reserve(8);
    let refused = v.try_reserve(usize::MAX);
    let refused_exact = v.try_reserve_exact(usize::MAX / 4);
    let _ = write!(
        text,
        "; try_reserve(8) {ok:?}, try_reserve(MAX) {refused:?}, try_reserve_exact(MAX/4) {}",
        refused_exact.is_err()
    );

    if cx.fault(FAULT_WITH_CAPACITY) {
        // Far past what either width can hold in bytes, so `Vec` refuses the
        // layout itself and never asks an allocator the host could fail.
        let count = usize::MAX - black_box(v.len());
        let huge: Vec<u64> = Vec::with_capacity(count);
        black_box(&huge);
    }

    let mut s = String::new();
    let mut q: VecDeque<u8> = VecDeque::new();
    let string_refused = s.try_reserve(usize::MAX).is_err();
    let deque_refused = q.try_reserve(usize::MAX).is_err();
    q.reserve_exact(k);
    let empty: Vec<u8> = Vec::with_capacity(0);
    let _ = write!(
        text,
        "; String::new {} refuses {string_refused}; VecDeque refuses {deque_refused} then holds \
         {}; with_capacity(0) {}",
        s.capacity(),
        q.capacity() >= k,
        empty.capacity()
    );

    let mut f = Fold::new();
    for x in &v {
        f.word(*x);
    }
    emit(cx, TAG_RESERVE, &text, &f);
}

/// Filling collections from iterators: with an exact size hint (one block),
/// with none (grown as it goes), and into maps and strings; a jagged
/// `Vec<Vec<u8>>` whose rows all grow at once, so their reallocations
/// interleave; `vec!`'s clone path and its zeroed path.
fn collect(cx: &mut Ctx) {
    let s = scale(cx) as u64;
    let mut f = Fold::new();

    // Exact hint.
    let mut numbers: Vec<u64> = (0..8 + 4 * s).map(|x| x * x).collect();
    let hinted = numbers.len();
    // A lower bound of 0.
    numbers.extend((0..24 + 12 * s).filter(|x| x % 3 == 1));
    // No bound at all, and a stop the data decides.
    let mut state = cx.rng().next_u32() | 1;
    numbers.extend(
        core::iter::from_fn(|| {
            state = state.wrapping_mul(0x2c92_77b5).wrapping_add(0xac56_4b05);
            (state >> 28 != 0).then_some(u64::from(state))
        })
        .take(12),
    );
    numbers.extend(core::iter::successors(Some(1u64), |x| {
        (*x < 1_000_000).then(|| x * 3)
    }));

    if cx.fault(FAULT_RESERVE) {
        // One more than fits beside the elements already there.
        let extra = usize::MAX - black_box(numbers.len()) + 1;
        numbers.reserve(extra);
    }

    // Text: the payload as given, or generated when there is none.
    let payload = cx.payload();
    let cut = payload.len().min(32 + 16 * s as usize);
    let text: Cow<'_, str> = if payload.is_empty() {
        let mut generated = String::new();
        for _ in 0..16 {
            let r = cx.rng().next_u32();
            generated.push(char::from(b"abc de,fg h"[(r % 11) as usize]));
        }
        Cow::Owned(generated)
    } else {
        String::from_utf8_lossy(&payload[..cut])
    };
    let last_seen: BTreeMap<&str, u32> = text
        .split_whitespace()
        .enumerate()
        .map(|(i, w)| (w, i as u32))
        .collect();
    let mut counts: BTreeMap<char, u32> = BTreeMap::new();
    for c in text.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let reversed: String = text.chars().rev().filter(|c| !c.is_whitespace()).collect();
    let fields: Vec<&str> = text.split(',').collect();
    let distinct: BTreeSet<char> = text.chars().filter(|c| c.is_alphanumeric()).collect();

    // Rows that all grow together.
    let rows = 4 + 2 * s as usize;
    let mut jagged: Vec<Vec<u8>> = vec![Vec::new(); rows];
    let targets: Vec<u8> = (0..rows).map(|_| cx.rng().below(16) as u8).collect();
    for round in 0..16u8 {
        for (row, &target) in jagged.iter_mut().zip(&targets) {
            if round < target {
                row.push(round ^ target);
            }
        }
    }

    // `vec!` of a non-zero `Vec` clones it; of zeros it asks for zeroed memory.
    let side = 3 + s as usize / 3;
    let mut grid = vec![vec![0u32; side]; side + 1];
    for (i, row) in grid.iter_mut().enumerate() {
        row[i % side] = i as u32 + 1;
    }
    let zeroed_len = 24 + 16 * s as usize;
    let mut zeroed = vec![0u64; zeroed_len];
    for k in (0..zeroed_len).step_by(13) {
        zeroed[k] = k as u64;
    }

    // A string three ways.
    let mut built = String::new();
    for (i, (word, at)) in last_seen.iter().take(4).enumerate() {
        built.push_str(word);
        built.push('|');
        let _ = write!(built, "{i:02x}:{at}");
        built += ";";
    }
    let formatted = format!("{:>8}|{:<6}|{:+}|{:#x}", "right", "left", 42i32, 255u32);

    for x in &numbers {
        f.word(*x);
    }
    for (w, at) in &last_seen {
        f.str(w).word(u64::from(*at));
    }
    for (c, n) in &counts {
        f.word(u64::from(*c)).word(u64::from(*n));
    }
    f.str(&reversed).count(fields.len()).count(distinct.len());
    for row in &jagged {
        f.bytes(row);
    }
    for row in &grid {
        for x in row {
            f.word(u64::from(*x));
        }
    }
    f.word(zeroed.iter().sum()).str(&built).str(&formatted);

    let summary = format!(
        "{} numbers ({hinted} hinted), {} words, {} chars, {} rows of {} bytes, grid {}x{side}, \
         {zeroed_len} zeroed, {formatted}",
        numbers.len(),
        last_seen.len(),
        counts.len(),
        jagged.len(),
        jagged.iter().map(Vec::len).sum::<usize>(),
        grid.len()
    );
    emit(cx, TAG_COLLECT, &summary, &f);
}

// ---------------------------------------------------------------------------
// (c) Over-aligned and zero-sized types
// ---------------------------------------------------------------------------

/// A cache line: an alignment no allocator gets by accident.
#[repr(align(64))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Line {
    words: [u32; 4],
}

#[derive(Clone, Copy)]
struct Marker;

/// Over-aligned blocks with one-byte blocks between them, so the bump has to
/// pad every one, asserted aligned on both legs — the answer is the same
/// boolean everywhere, and an address never reaches the output. Then
/// zero-sized types, of which a million allocate nothing at all.
// One block per `Line` is the point.
#[allow(clippy::vec_box)]
fn align_and_zst(cx: &mut Ctx) {
    let n = 4 + 3 * scale(cx);
    let mut lines: Vec<Line> = Vec::new();
    let mut boxed: Vec<Box<Line>> = Vec::new();
    let mut spacers: Vec<Box<u8>> = Vec::new();
    for i in 0..n {
        let r = cx.rng().next_u64();
        spacers.push(Box::new(r as u8));
        let line = Line {
            words: [r as u32, (r >> 32) as u32, i as u32, 0xa11a],
        };
        boxed.push(Box::new(line));
        lines.push(line);
        assert!(
            core::ptr::from_ref::<Line>(&boxed[i]).is_aligned(),
            "a Box<Line> is not 64-aligned"
        );
        assert!(lines.as_ptr().is_aligned(), "a Vec<Line> is not 64-aligned");
    }
    let wide = Box::new(u128::MAX / 3 + u128::from(*spacers[0]));
    assert!(
        core::ptr::from_ref::<u128>(&wide).is_aligned(),
        "a Box<u128> is misaligned"
    );
    let slice: Box<[Line]> = lines.clone().into_boxed_slice();
    assert!(
        slice.iter().all(|l| core::ptr::from_ref(l).is_aligned()),
        "a Box<[Line]> element is not 64-aligned"
    );
    let same = boxed.iter().zip(slice.iter()).all(|(b, l)| **b == *l);

    let mut units = vec![(); 1_000_000];
    units.push(());
    units.pop();
    let unbounded = units.capacity() == usize::MAX;
    let mut rest = units.split_off(999_000);
    rest.truncate(500 + cx.rng().index(100));
    let drained = rest.drain(..10).count();
    // Dropping a `Vec` runs the slice drop glue once per element even for an
    // element that needs no drop, so dropping the 999_000 here would cost the
    // guest eight million instructions at opt-level 0. Forgetting it leaks
    // nothing: a zero-sized element never allocated a byte.
    mem::forget(units);
    let unit_box = Box::new(());
    let unit_array: Box<[(); 7]> = Box::new([(); 7]);
    let markers = vec![Marker; 8 + scale(cx)];
    let ranks: u32 = markers.iter().zip(1u32..).map(|(_, i)| i).sum();
    black_box((&unit_box, &unit_array));

    let mut f = Fold::new();
    for (line, spacer) in boxed.iter().zip(&spacers) {
        f.word(u64::from(**spacer));
        for w in line.words {
            f.word(u64::from(w));
        }
    }
    f.word(*wide as u64).word((*wide >> 64) as u64);
    let summary = format!(
        "{n} lines aligned in Box, Vec and Box<[_]>, equal {same}; a million units, {} left \
         after a split and a drain of {drained}, capacity unbounded {unbounded}; {} unit array, \
         {} markers rank sum {ranks}",
        rest.len(),
        unit_array.len(),
        markers.len()
    );
    emit(cx, TAG_ALIGN_ZST, &summary, &f);
}

// ---------------------------------------------------------------------------
// (d) Containers that reorganize
// ---------------------------------------------------------------------------

/// A ring buffer pushed at both ends and popped at the front, so its head
/// walks and later pushes wrap past the end of the block: each growth then
/// has to unwrap the ring into the new block in order.
fn deque(cx: &mut Ctx) {
    let n = 16 + 16 * scale(cx);
    let mut q: VecDeque<u32> = VecDeque::with_capacity(4);
    let mut f = Fold::new();
    let mut regrowths = 0u32;
    let mut cap = q.capacity();
    let mut wrapped_growths = 0u32;
    for i in 0..n {
        let r = cx.rng().next_u32();
        let wrapped_before = !q.as_slices().1.is_empty();
        match r % 4 {
            0 | 1 => q.push_back(r),
            2 => q.push_front(r),
            _ => {
                if let Some(x) = q.pop_front() {
                    f.word(u64::from(x));
                }
                q.push_back(i as u32);
            }
        }
        if i % 5 == 0 {
            if let Some(x) = q.pop_back() {
                f.word(u64::from(x));
            }
        }
        if q.capacity() != cap {
            regrowths += 1;
            wrapped_growths += u32::from(wrapped_before);
            cap = q.capacity();
        }
    }
    let (front, back) = q.as_slices();
    f.count(front.len()).count(back.len());
    for x in q.iter().rev() {
        f.word(u64::from(*x));
    }

    let third = q.len() / 3;
    q.rotate_left(third);
    q.retain(|x| x % 7 != 3);
    let hi = q.len().min(9);
    let window: Vec<u32> = q.range(hi.min(1)..hi).copied().collect();
    if q.len() >= 2 {
        let last = q.len() - 1;
        q.swap(0, last);
        let mid = q.len() / 2;
        q.insert(mid, 0xdead);
        q.remove(1);
    }
    let mut tail = q.split_off(q.len() / 2);
    tail.extend(window.iter().map(|x| x ^ 1));
    q.append(&mut tail);
    q.make_contiguous().sort_unstable();
    let pivot = window.first().copied().unwrap_or(u32::MAX / 2);
    let below = q.partition_point(|&x| x < pivot);
    let drained: u64 = q.drain(..q.len().min(4)).map(u64::from).sum();
    for x in &q {
        f.word(u64::from(*x));
    }
    f.word(drained);

    let summary = format!(
        "{n} steps, {regrowths} regrowths ({wrapped_growths} while wrapped), len {}, {below} \
         below {pivot}",
        q.len()
    );
    emit(cx, TAG_DEQUE, &summary, &f);
}

/// A B-tree through inserts that split nodes, overwrites, removals that merge
/// them, the entry API, a split and a re-merge, and set algebra over its keys.
fn btree(cx: &mut Ctx) {
    let n = 8 + 12 * scale(cx);
    // Keys drawn from four times as many as are inserted, so some collide.
    let space = 4 * n as u32;
    let mut map: BTreeMap<u32, u64> = BTreeMap::new();
    let mut replaced = 0u32;
    for i in 0..n {
        let k = cx.rng().below(u64::from(space)) as u32;
        replaced += u32::from(map.insert(k, i as u64).is_some());
    }
    let inserted = map.len();
    let mut removed = 0u32;
    for _ in 0..n / 3 {
        let k = cx.rng().below(u64::from(space)) as u32;
        removed += u32::from(map.remove(&k).is_some());
    }
    for _ in 0..n / 4 {
        let k = cx.rng().below(u64::from(space)) as u32;
        map.entry(k)
            .and_modify(|v| *v = v.wrapping_mul(3))
            .or_insert(7);
    }
    let range_sum = map
        .range(space / 4..space / 2)
        .map(|(_, v)| *v)
        .fold(0u64, u64::wrapping_add);
    let first = map.first_key_value().map(|(k, v)| (*k, *v));
    let last = map.pop_last();
    map.retain(|k, v| !(k ^ *v as u32).is_multiple_of(11));
    let mut upper = map.split_off(&(space / 2));
    let lower_len = map.len();
    for v in upper.values_mut() {
        *v += 1;
    }
    map.append(&mut upper);

    let evens: BTreeSet<u32> = map
        .keys()
        .filter(|k| k.is_multiple_of(2))
        .copied()
        .collect();
    let thirds: BTreeSet<u32> = map
        .keys()
        .filter(|k| k.is_multiple_of(3))
        .copied()
        .collect();
    let both = evens.intersection(&thirds).count();
    let either = evens.symmetric_difference(&thirds).count();

    let mut f = Fold::new();
    for (k, v) in &map {
        f.word(u64::from(*k)).word(*v);
    }
    for k in thirds.range(..space / 3).rev() {
        f.word(u64::from(*k));
    }
    f.word(range_sum);
    if let Some((k, v)) = first {
        f.word(u64::from(k)).word(v);
    }
    if let Some((k, v)) = last {
        f.word(u64::from(k)).word(v);
    }
    let summary = format!(
        "{n} inserts ({replaced} replaced, {inserted} keys), {removed} removed, {} after retain \
         ({lower_len} below the split); sets {both} {either}",
        map.len()
    );
    emit(cx, TAG_BTREE, &summary, &f);
}

/// A binary heap grown by pushes, drained in part, edited through `peek_mut`,
/// merged, and then run as a min-heap in Dijkstra's algorithm. Every element
/// is distinct under `Ord`, so which of two equal ones pops first — which the
/// heap leaves unspecified — never arises.
fn heap(cx: &mut Ctx) {
    let n = 8 + 12 * scale(cx);
    let mut heap: BinaryHeap<(u32, u16)> = BinaryHeap::new();
    for i in 0..n {
        heap.push((cx.rng().below(64) as u32, i as u16));
    }
    let mut f = Fold::new();
    for _ in 0..n / 3 {
        if let Some((a, b)) = heap.pop() {
            f.word(u64::from(a)).word(u64::from(b));
        }
    }
    if let Some(mut top) = heap.peek_mut() {
        top.0 /= 2;
    }
    heap.retain(|(a, _)| a % 5 != 0);
    let mut other: BinaryHeap<(u32, u16)> =
        (0..8u16).map(|i| (u32::from(i) * 4, 1000 + i)).collect();
    heap.append(&mut other);
    heap.extend((0..4u16).map(|i| (u32::from(i) * 9, 2000 + i)));
    let sorted = heap.clone().into_sorted_vec();
    for (a, b) in &sorted {
        f.word(u64::from(*a)).word(u64::from(*b));
    }

    // Dijkstra over a grid of random weights. Equal distances may pop in
    // either order; the distances they settle to may not differ.
    let w = 4 + scale(cx) / 6;
    let weights: Vec<u32> = (0..w * w).map(|_| 1 + cx.rng().below(9) as u32).collect();
    let mut dist = vec![u32::MAX; w * w];
    let mut frontier = BinaryHeap::new();
    dist[0] = 0;
    frontier.push(Reverse((0u32, 0u16)));
    let mut settled = 0u32;
    while let Some(Reverse((du, u))) = frontier.pop() {
        let u = usize::from(u);
        if du > dist[u] {
            continue;
        }
        settled += 1;
        let (x, y) = (u % w, u / w);
        let mut next = Vec::with_capacity(4);
        if x > 0 {
            next.push(u - 1);
        }
        if x + 1 < w {
            next.push(u + 1);
        }
        if y > 0 {
            next.push(u - w);
        }
        if y + 1 < w {
            next.push(u + w);
        }
        for v in next {
            let dv = du + weights[v];
            if dv < dist[v] {
                dist[v] = dv;
                frontier.push(Reverse((dv, v as u16)));
            }
        }
    }
    for x in &dist {
        f.word(u64::from(*x));
    }
    let summary = format!(
        "{n} pushed, {} after merging, top {:?}; {w}x{w} grid settled {settled}, corner {}",
        sorted.len(),
        sorted.last(),
        dist[w * w - 1]
    );
    emit(cx, TAG_HEAP, &summary, &f);
}

// ---------------------------------------------------------------------------
// (e) Ownership moves
// ---------------------------------------------------------------------------

/// Large enough that a move is a real copy, and owning blocks of its own.
#[derive(Clone, Debug, Default, PartialEq)]
struct Ledger {
    totals: [u64; 8],
    entries: Vec<u32>,
    label: String,
    note: Option<Box<[u8]>>,
}

fn ledger(cx: &mut Ctx, salt: u8) -> Ledger {
    let mut totals = [0u64; 8];
    for t in totals.iter_mut() {
        *t = cx.rng().next_u64() >> 8;
    }
    let len = 4 + cx.rng().index(8);
    let entries = (0..len).map(|_| cx.rng().next_u32()).collect();
    let mut label = String::from("ledger-");
    label.push(char::from(b'a' + salt));
    let note = cx.rng().chance(1, 2).then(|| Box::from(&[salt; 5][..]));
    Ledger {
        totals,
        entries,
        label,
        note,
    }
}

struct Link {
    value: u32,
    next: Option<Box<Link>>,
}

/// A singly linked list of boxes, built and reversed by moving `Option`s.
struct Chain {
    head: Option<Box<Link>>,
}

impl Chain {
    fn push(&mut self, value: u32) {
        let next = self.head.take();
        self.head = Some(Box::new(Link { value, next }));
    }

    fn pop(&mut self) -> Option<u32> {
        let link = self.head.take()?;
        let Link { value, next } = *link;
        self.head = next;
        Some(value)
    }

    fn reverse(&mut self) {
        let mut done = None;
        let mut rest = self.head.take();
        while let Some(mut link) = rest {
            rest = mem::replace(&mut link.next, done);
            done = Some(link);
        }
        self.head = done;
    }

    fn values(&self) -> Vec<u32> {
        let mut values = Vec::new();
        let mut at = self.head.as_deref();
        while let Some(link) = at {
            values.push(link.value);
            at = link.next.as_deref();
        }
        values
    }
}

/// One node at a time: the derived drop would recurse once per link.
impl Drop for Chain {
    fn drop(&mut self) {
        let mut rest = self.head.take();
        while let Some(mut link) = rest {
            rest = link.next.take();
        }
    }
}

/// `mem::swap`, `take` and `replace` on structs that own blocks, and
/// `Option::take`/`replace`/`get_or_insert_with`: the moved-from side must be
/// exactly what the API says, and the moved-to side the whole value.
fn moves(cx: &mut Ctx) {
    let mut a = ledger(cx, 0);
    let mut b = ledger(cx, 1);
    let first_a = a.clone();
    mem::swap(&mut a, &mut b);
    let swapped = b == first_a;
    let taken = mem::take(&mut a);
    let emptied = a == Ledger::default();
    let mut old = mem::replace(&mut b, taken.clone());
    let note = b.note.take();
    let prior = b.note.replace(Box::from(&b"replaced"[..]));
    let fresh = old
        .note
        .get_or_insert_with(|| Box::from(&b"inserted"[..]))
        .len();
    b.totals[..4].swap_with_slice(&mut old.totals[..4]);
    mem::swap(&mut b.entries, &mut old.entries);
    let label = mem::take(&mut old.label);

    let mut slot: Option<Box<Ledger>> = Some(Box::new(old));
    let unboxed = slot.take().map(|boxed| *boxed);
    let mut ledgers = vec![a, b, taken];
    ledgers.extend(unboxed);
    let (i, j) = (cx.rng().index(ledgers.len()), cx.rng().index(ledgers.len()));
    ledgers.swap(i, j);
    let entries = mem::take(&mut ledgers[j].entries);
    ledgers[i].entries.extend(entries);

    let n = 8 + 8 * scale(cx);
    let mut chain = Chain { head: None };
    for _ in 0..n {
        chain.push(cx.rng().next_u32());
    }
    let mut popped = 0u64;
    for _ in 0..n / 4 {
        popped += u64::from(chain.pop().unwrap_or(0));
    }
    chain.reverse();
    let values = chain.values();

    let mut f = Fold::new();
    for l in &ledgers {
        for t in l.totals {
            f.word(t);
        }
        for e in &l.entries {
            f.word(u64::from(*e));
        }
        f.str(&l.label);
        if let Some(note) = &l.note {
            f.bytes(note);
        }
    }
    for v in &values {
        f.word(u64::from(*v));
    }
    f.word(popped);
    let summary = format!(
        "swapped {swapped}, emptied {emptied}, note taken {} prior {}, inserted {fresh}, label \
         {label}, {} ledgers, chain of {} after {} pops",
        note.is_some(),
        prior.is_some(),
        ledgers.len(),
        values.len(),
        n / 4
    );
    emit(cx, TAG_MOVES, &summary, &f);
}

/// NUL bytes as spaces, allocating only when there is one to replace.
fn denul(bytes: &[u8]) -> Cow<'_, [u8]> {
    if bytes.contains(&0) {
        Cow::Owned(
            bytes
                .iter()
                .map(|&b| if b == 0 { b' ' } else { b })
                .collect(),
        )
    } else {
        Cow::Borrowed(bytes)
    }
}

/// Which path a `Cow` took: `b`orrowed or `o`wned.
// The variant is the answer, so this has to see the `Cow` and not what it
// dereferences to.
#[allow(clippy::ptr_arg)]
fn kind<B: ?Sized + alloc::borrow::ToOwned>(cow: &Cow<'_, B>) -> char {
    match cow {
        Cow::Borrowed(_) => 'b',
        Cow::Owned(_) => 'o',
    }
}

/// `Cow` taking its borrowed path or its owned one by what the data holds —
/// the payload's own UTF-8 validity and NULs — and `to_mut` turning a borrowed
/// one owned.
fn cow(cx: &mut Ctx) {
    let payload = cx.payload();
    let data: Cow<'_, [u8]> = if payload.is_empty() {
        let mut bytes = cx.rng().bytes(48);
        for b in bytes.iter_mut() {
            // Mostly ASCII, some NULs, some bytes no UTF-8 sequence starts with.
            *b = match *b % 16 {
                0 => 0,
                1 => 0xff,
                x => b'a' + x,
            };
        }
        Cow::Owned(bytes)
    } else {
        Cow::Borrowed(payload)
    };
    let width = 5 + scale(cx);
    let chunks = 6 + 2 * scale(cx);

    let mut f = Fold::new();
    let mut lossy_kinds = String::new();
    let mut denul_kinds = String::new();
    for chunk in data.chunks(width).take(chunks) {
        let lossy = String::from_utf8_lossy(chunk);
        lossy_kinds.push(kind(&lossy));
        f.str(&lossy);
        let mut clean = denul(chunk);
        denul_kinds.push(kind(&clean));
        if clean.len() > 3 {
            clean.to_mut()[0] ^= 0x20;
            denul_kinds.push(kind(&clean));
        }
        f.bytes(&clean);
    }

    let mut label: Cow<'static, str> = Cow::Borrowed("static");
    let before = kind(&label);
    label.to_mut().push_str("+owned");
    let after = kind(&label);
    let owned: String = Cow::Borrowed("into_owned").into_owned();
    let from_vec: Cow<'_, [u8]> = Cow::from(data[..data.len().min(16)].to_vec());
    f.str(&label).str(&owned).bytes(&from_vec);

    let summary = format!(
        "data {} of {}, lossy {lossy_kinds}, denul {denul_kinds}, label {before}{after} {label}",
        kind(&data),
        data.len()
    );
    emit(cx, TAG_COW, &summary, &f);
}

/// The book's tree: children own their nodes, parents are `Weak`, so dropping
/// the root frees the lot where a strong parent pointer would leak a cycle.
struct TreeNode {
    value: u32,
    parent: RefCell<Weak<TreeNode>>,
    children: RefCell<Vec<Rc<TreeNode>>>,
}

/// A doubly linked pair: one strong edge, one weak.
struct Pair {
    value: u32,
    next: Option<Rc<RefCell<Pair>>>,
    back: Weak<RefCell<Pair>>,
}

/// `Rc`/`Weak` counts through a tree built at random, a cycle broken by a
/// `Weak`, and `make_mut`'s clone-on-write.
fn rc(cx: &mut Ctx) {
    let n = 6 + 6 * scale(cx);
    let mut nodes: Vec<Rc<TreeNode>> = Vec::with_capacity(n);
    for i in 0..n {
        let node = Rc::new(TreeNode {
            value: cx.rng().next_u32() >> 4,
            parent: RefCell::new(Weak::new()),
            children: RefCell::new(Vec::new()),
        });
        if i > 0 {
            let parent = &nodes[cx.rng().index(i)];
            parent.children.borrow_mut().push(Rc::clone(&node));
            *node.parent.borrow_mut() = Rc::downgrade(parent);
        }
        nodes.push(node);
    }

    if cx.fault(FAULT_BORROW) {
        let victim = &nodes[black_box(cx.rng().index(n))];
        let held = victim.children.borrow_mut();
        let again = victim.children.borrow();
        black_box((&held, &again));
    }

    // Depths and path sums by walking up the weak parent pointers, over the
    // last few nodes: walking every one is quadratic in the tree's depth.
    let mut f = Fold::new();
    let mut depth_sum = 0u64;
    for node in nodes.iter().rev().take(8) {
        let mut depth = 0u64;
        let mut sum = u64::from(node.value);
        let mut up = node.parent.borrow().upgrade();
        while let Some(p) = up {
            depth += 1;
            sum += u64::from(p.value);
            up = p.parent.borrow().upgrade();
        }
        depth_sum += depth;
        f.word(sum);
        f.count(Rc::strong_count(node)).count(Rc::weak_count(node));
    }
    let root = Rc::clone(&nodes[0]);
    let leaf = Rc::downgrade(&nodes[n - 1]);
    let (root_strong, root_weak) = (Rc::strong_count(&root), Rc::weak_count(&root));
    drop(nodes);
    let leaf_alive = leaf.upgrade().is_some();
    let root_after = Rc::strong_count(&root);
    drop(root);
    let leaf_after_root = leaf.upgrade().is_some();

    let a = Rc::new(RefCell::new(Pair {
        value: 1,
        next: None,
        back: Weak::new(),
    }));
    let b = Rc::new(RefCell::new(Pair {
        value: 2,
        next: None,
        back: Rc::downgrade(&a),
    }));
    a.borrow_mut().next = Some(Rc::clone(&b));
    let back_value = b.borrow().back.upgrade().map_or(0, |p| p.borrow().value);
    let next_value = a.borrow().next.as_ref().map_or(0, |p| p.borrow().value);
    let counts = (
        Rc::strong_count(&a),
        Rc::weak_count(&a),
        Rc::strong_count(&b),
    );
    let weak_b = Rc::downgrade(&b);
    drop(b);
    let b_held = weak_b.upgrade().is_some();
    drop(a);
    let b_freed = weak_b.upgrade().is_none();

    let mut shared = Rc::new(vec![1u32, 2, 3]);
    let other = Rc::clone(&shared);
    Rc::make_mut(&mut shared).push(4);
    let cloned = !Rc::ptr_eq(&shared, &other);
    let unwrapped = Rc::try_unwrap(other).map(|v| v.len());
    let refused = Rc::try_unwrap(Rc::clone(&shared)).is_err();
    let slice: Rc<[u32]> = Rc::from(shared.as_slice());
    f.word(u64::from(slice.iter().sum::<u32>()));

    let summary = format!(
        "{n} nodes, depth sum {depth_sum}, root {root_strong}/{root_weak} then {root_after}, \
         leaf alive {leaf_alive} then {leaf_after_root}; pair {back_value}<->{next_value} counts \
         {counts:?}, held {b_held} freed {b_freed}; make_mut cloned {cloned}, try_unwrap \
         {unwrapped:?} refused {refused}"
    );
    emit(cx, TAG_RC, &summary, &f);
}

trait Shape {
    fn area(&self) -> u64;
    fn name(&self) -> &'static str;
}

struct Square(u32);

struct Rect {
    w: u16,
    h: u16,
}

/// Twice its area, by the shoelace formula.
struct Polygon(Vec<(i32, i32)>);

impl Shape for Square {
    fn area(&self) -> u64 {
        u64::from(self.0) * u64::from(self.0)
    }
    fn name(&self) -> &'static str {
        "square"
    }
}

impl Shape for Rect {
    fn area(&self) -> u64 {
        u64::from(self.w) * u64::from(self.h)
    }
    fn name(&self) -> &'static str {
        "rect"
    }
}

impl Shape for Polygon {
    fn area(&self) -> u64 {
        let n = self.0.len();
        let twice: i64 = (0..n)
            .map(|i| {
                let (a, b) = (self.0[i], self.0[(i + 1) % n]);
                i64::from(a.0) * i64::from(b.1) - i64::from(b.0) * i64::from(a.1)
            })
            .sum();
        twice.unsigned_abs()
    }
    fn name(&self) -> &'static str {
        "polygon"
    }
}

/// An over-aligned trait object: its vtable carries the 64.
impl Shape for Line {
    fn area(&self) -> u64 {
        self.words.iter().map(|w| u64::from(*w)).sum()
    }
    fn name(&self) -> &'static str {
        "line"
    }
}

/// Which type an `Any` holds, as a letter, folding its value into `f`.
fn classify(value: &dyn Any, f: &mut Fold) -> char {
    if let Some(v) = value.downcast_ref::<u8>() {
        f.word(u64::from(*v));
        'b'
    } else if let Some(v) = value.downcast_ref::<u64>() {
        f.word(*v);
        'w'
    } else if let Some(v) = value.downcast_ref::<u128>() {
        f.word(*v as u64).word((*v >> 64) as u64);
        'x'
    } else if let Some(v) = value.downcast_ref::<String>() {
        f.str(v);
        's'
    } else if let Some(v) = value.downcast_ref::<Vec<u16>>() {
        f.count(v.len());
        'v'
    } else if let Some(v) = value.downcast_ref::<Line>() {
        assert!(
            core::ptr::from_ref(v).is_aligned(),
            "a boxed Any Line is not 64-aligned"
        );
        f.word(u64::from(v.words[0]));
        'l'
    } else if value.is::<()>() {
        'u'
    } else if value.is::<Marker>() {
        'm'
    } else {
        '?'
    }
}

/// `Box<dyn Any>` of values of every size and alignment, zero-sized ones
/// included, told apart by `downcast_ref` and taken apart by `downcast`'s `Ok`
/// and `Err`; trait objects and boxed closures whose captures differ in size.
fn any(cx: &mut Ctx) {
    let n = 6 + 6 * scale(cx);
    let mut values: Vec<Box<dyn Any>> = Vec::with_capacity(n);
    for i in 0..n {
        let r = cx.rng().next_u64();
        let value: Box<dyn Any> = match r % 8 {
            0 => Box::new(r as u8),
            1 => Box::new(r),
            2 => Box::new((u128::from(r) << 64) | i as u128),
            3 => Box::new(String::from(["one", "two", "three"][(r % 3) as usize])),
            4 => Box::new(vec![r as u16; (r >> 61) as usize]),
            5 => Box::new(Line {
                words: [r as u32, 0, 0, i as u32],
            }),
            6 => Box::new(()),
            _ => Box::new(Marker),
        };
        values.push(value);
    }
    let mut f = Fold::new();
    let mut kinds = String::new();
    for value in &values {
        // `&**value`: a `&Box<dyn Any>` would itself coerce to `&dyn Any`, and
        // every downcast would then fail.
        kinds.push(classify(&**value, &mut f));
    }

    let mut strings = Vec::new();
    let mut vectors = Vec::new();
    let mut rest = Vec::new();
    for value in values {
        match value.downcast::<String>() {
            Ok(s) => strings.push(*s),
            Err(value) => match value.downcast::<Vec<u16>>() {
                Ok(v) => vectors.push(*v),
                Err(value) => rest.push(value),
            },
        }
    }
    for s in &strings {
        f.str(s);
    }

    if cx.fault(FAULT_DOWNCAST) {
        // Nothing left in `rest` is a `u16`, whichever value this is.
        let probe = rest
            .pop()
            .unwrap_or_else(|| Box::new(black_box(0u64)) as Box<dyn Any>);
        let wrong: Box<u16> = probe.downcast::<u16>().unwrap();
        black_box(wrong);
    }

    let r = cx.rng().next_u64();
    let shapes: Vec<Box<dyn Shape>> = vec![
        Box::new(Square(r as u32 >> 20)),
        Box::new(Rect {
            w: r as u16,
            h: (r >> 16) as u16,
        }),
        Box::new(Polygon(vec![
            (0, 0),
            (r as i32 >> 12, 0),
            (0, (r >> 32) as i32 >> 12),
        ])),
        Box::new(Line {
            words: [1, 2, 3, r as u32],
        }),
    ];
    let area = shapes
        .iter()
        .map(|s| s.area())
        .fold(0u64, u64::wrapping_add);
    let names: Vec<&str> = shapes.iter().map(|s| s.name()).collect();

    let table: Vec<u64> = (0..8).map(|_| cx.rng().next_u64() >> 40).collect();
    let wide = u128::from(cx.rng().next_u64());
    let k = cx.rng().next_u64() | 1;
    let steps: Vec<Box<dyn Fn(u64) -> u64>> = vec![
        Box::new(|x| x.rotate_left(7)),
        Box::new(move |x| x.wrapping_mul(k)),
        Box::new(move |x| ((wide * u128::from(x)) >> 32) as u64),
        Box::new(move |x| table[(x % 8) as usize] ^ x),
    ];
    let mut acc = r;
    for _ in 0..4 + scale(cx) {
        for step in &steps {
            acc = step(acc);
        }
    }
    let mut calls = 0u32;
    let mut counter: Box<dyn FnMut(u64) -> u64> = Box::new(|x| {
        calls += 1;
        x ^ u64::from(calls)
    });
    let counted = counter(acc);
    drop(counter);
    f.word(counted).word(area);

    let summary = format!(
        "{n} values {}, {} strings, {} vectors, {} other; shapes {} area {area}; closures \
         {acc:016x} after {calls} counted call",
        &kinds[..kinds.len().min(32)],
        strings.len(),
        vectors.len(),
        rest.len(),
        names.join(",")
    );
    emit(cx, TAG_ANY, &summary, &f);
}

// ---------------------------------------------------------------------------
// (f) Allocators in safe Rust
// ---------------------------------------------------------------------------

/// The arena's null index.
const NIL: u32 = u32::MAX;

#[derive(Clone, Copy)]
enum Op {
    Const(i32),
    Var,
    Add,
    Sub,
    Mul,
    Neg,
}

impl Op {
    fn arity(self) -> usize {
        match self {
            Op::Const(_) | Op::Var => 0,
            Op::Neg => 1,
            Op::Add | Op::Sub | Op::Mul => 2,
        }
    }
}

#[derive(Clone, Copy)]
struct Expr {
    op: Op,
    kids: [u32; 2],
}

enum Slot {
    Live(Expr),
    Free { next: u32 },
}

/// Expression nodes in one `Vec`, addressed by `u32` index, with freed slots
/// threaded into a free list and handed out again: an allocator with reuse,
/// which the guest's own heap does not have, in safe Rust.
struct Arena {
    slots: Vec<Slot>,
    free: u32,
    live: u32,
    peak: u32,
    reused: u32,
}

impl Arena {
    fn alloc(&mut self, expr: Expr) -> u32 {
        self.live += 1;
        self.peak = self.peak.max(self.live);
        if self.free == NIL {
            self.slots.push(Slot::Live(expr));
            return (self.slots.len() - 1) as u32;
        }
        let at = self.free;
        match self.slots[at as usize] {
            Slot::Free { next } => self.free = next,
            Slot::Live(_) => panic!("the free list reached live slot {at}"),
        }
        self.slots[at as usize] = Slot::Live(expr);
        self.reused += 1;
        at
    }

    fn get(&self, at: u32) -> Expr {
        match self.slots[at as usize] {
            Slot::Live(expr) => expr,
            Slot::Free { .. } => panic!("slot {at} used after it was freed"),
        }
    }

    /// Free `at` and everything under it.
    fn release(&mut self, at: u32) {
        let expr = self.get(at);
        for &kid in &expr.kids[..expr.op.arity()] {
            self.release(kid);
        }
        self.slots[at as usize] = Slot::Free { next: self.free };
        self.free = at;
        self.live -= 1;
    }

    fn build(&mut self, rng: &mut Rng, depth: u32) -> u32 {
        let r = rng.next_u32();
        let op = if depth == 0 || r % 8 < 2 {
            if r & 0x100 == 0 {
                Op::Var
            } else {
                Op::Const((r >> 12) as i32 - (1 << 19))
            }
        } else {
            match r % 8 {
                2 | 3 => Op::Add,
                4 => Op::Sub,
                5 | 6 => Op::Mul,
                _ => Op::Neg,
            }
        };
        let mut kids = [NIL; 2];
        for kid in kids.iter_mut().take(op.arity()) {
            *kid = self.build(rng, depth - 1);
        }
        self.alloc(Expr { op, kids })
    }

    fn eval(&self, at: u32, x: i32) -> i32 {
        let expr = self.get(at);
        let kid = |k: usize| self.eval(expr.kids[k], x);
        match expr.op {
            Op::Const(c) => c,
            Op::Var => x,
            Op::Add => kid(0).wrapping_add(kid(1)),
            Op::Sub => kid(0).wrapping_sub(kid(1)),
            Op::Mul => kid(0).wrapping_mul(kid(1)),
            Op::Neg => kid(0).wrapping_neg(),
        }
    }

    /// Constant folding: a node whose operands are all constants is freed with
    /// them and replaced by a fresh `Const` — which takes the slot just freed.
    fn fold(&mut self, at: u32) -> u32 {
        let mut expr = self.get(at);
        let arity = expr.op.arity();
        if arity == 0 {
            return at;
        }
        for k in 0..arity {
            expr.kids[k] = self.fold(expr.kids[k]);
        }
        self.slots[at as usize] = Slot::Live(expr);
        let constant = expr.kids[..arity]
            .iter()
            .all(|&kid| matches!(self.get(kid).op, Op::Const(_)));
        if !constant {
            return at;
        }
        let value = self.eval(at, 0);
        self.release(at);
        self.alloc(Expr {
            op: Op::Const(value),
            kids: [NIL; 2],
        })
    }
}

/// First fit over `(offset, len)` free blocks sorted by offset, coalescing on
/// free: a heap simulated in safe Rust, whose offsets are its only output.
struct FirstFit {
    free: Vec<(u32, u32)>,
}

impl FirstFit {
    fn malloc(&mut self, len: u32) -> Option<u32> {
        let i = self.free.iter().position(|&(_, l)| l >= len)?;
        let (at, l) = self.free[i];
        if l == len {
            self.free.remove(i);
        } else {
            self.free[i] = (at + len, l - len);
        }
        Some(at)
    }

    fn release(&mut self, at: u32, len: u32) {
        let i = self.free.partition_point(|&(o, _)| o < at);
        self.free.insert(i, (at, len));
        if i + 1 < self.free.len() && at + len == self.free[i + 1].0 {
            self.free[i].1 += self.free[i + 1].1;
            self.free.remove(i + 1);
        }
        if i > 0 && self.free[i - 1].0 + self.free[i - 1].1 == at {
            self.free[i - 1].1 += self.free[i].1;
            self.free.remove(i);
        }
    }
}

/// Expression trees built, evaluated, constant-folded and freed in an index
/// arena, a few kept alive at a time so freed slots are reused while others
/// are live; then a simulated first-fit heap under random mallocs and frees.
fn arena(cx: &mut Ctx) {
    let rounds = 3 + 2 * scale(cx);
    let depth = 5 + cx.scale() / 8;
    let mut arena = Arena {
        slots: Vec::new(),
        free: NIL,
        live: 0,
        peak: 0,
        reused: 0,
    };
    let mut alive: VecDeque<u32> = VecDeque::new();
    let mut f = Fold::new();
    let mut agree = true;
    for round in 0..rounds {
        let root = arena.build(cx.rng(), depth);
        let x = round as i32 - 3;
        let before = arena.eval(root, x);
        let root = arena.fold(root);
        let after = arena.eval(root, x);
        agree &= before == after;
        f.word(after as u32 as u64);
        alive.push_back(root);
        if alive.len() > 3 {
            if let Some(oldest) = alive.pop_front() {
                arena.release(oldest);
            }
        }
    }

    const SIZE: u32 = 4096;
    let mut heap = FirstFit {
        free: vec![(0, SIZE)],
    };
    let mut held: Vec<(u32, u32)> = Vec::new();
    let mut refused = 0u32;
    let mut most_fragments = 1usize;
    for _ in 0..12 + 12 * scale(cx) {
        if held.is_empty() || cx.rng().chance(3, 5) {
            let len = 1 + cx.rng().below(300) as u32;
            match heap.malloc(len) {
                Some(at) => {
                    f.word(u64::from(at));
                    held.push((at, len));
                }
                None => refused += 1,
            }
        } else {
            let (at, len) = held.swap_remove(cx.rng().index(held.len()));
            heap.release(at, len);
        }
        most_fragments = most_fragments.max(heap.free.len());
    }
    let still_held = held.len();
    for (at, len) in held {
        heap.release(at, len);
    }
    let coalesced = heap.free == [(0, SIZE)];

    let summary = format!(
        "{rounds} trees of depth {depth}, folding agrees {agree}; {} slots, {} live, peak {}, {} \
         reused; first fit refused {refused}, {still_held} held, at most {most_fragments} \
         fragments, coalesced {coalesced}",
        arena.slots.len(),
        arena.live,
        arena.peak,
        arena.reused
    );
    emit(cx, TAG_ARENA, &summary, &f);
}

// ---------------------------------------------------------------------------
// (g) Deep clones
// ---------------------------------------------------------------------------

type Nested = Vec<BTreeMap<String, Vec<u32>>>;

/// A nested structure cloned deep, compared equal, changed in one leaf and
/// compared unequal; `clone_from`'s reuse path; a shared `Rc` beside a deep
/// copy of what it points to.
fn deep_clone(cx: &mut Ctx) {
    let maps = 2 + scale(cx) / 4;
    let keys = 3 + scale(cx) / 3;
    let mut original: Nested = Vec::with_capacity(maps);
    for _ in 0..maps {
        let mut map = BTreeMap::new();
        for _ in 0..keys {
            let r = cx.rng().next_u64();
            let mut key = String::new();
            for k in 0..1 + r % 6 {
                key.push(char::from(b'a' + ((r >> (8 + 4 * k)) % 26) as u8));
            }
            let len = (r >> 40) as u32 % 8;
            map.insert(key, (0..len).map(|x| x ^ r as u32).collect());
        }
        original.push(map);
    }

    let mut copy = original.clone();
    let equal = copy == original;
    let target = cx.rng().index(copy.len());
    let at = cx.rng().index(copy[target].len());
    if let Some(v) = copy[target].values_mut().nth(at) {
        v.push(u32::MAX);
    }
    let unequal = copy != original;
    let order = original.cmp(&copy);
    let untouched = original.iter().zip(&copy).filter(|(a, b)| a == b).count();

    let mut reused: Nested = vec![BTreeMap::new(); 2];
    reused.clone_from(&original);
    let reused_equal = reused == original;
    let mut name = String::from("a string with capacity to spare");
    if let Some(key) = original[0].keys().next() {
        name.clone_from(key);
    }

    let shared = Rc::new(original);
    let alias = Rc::clone(&shared);
    let deep: Nested = (*shared).clone();
    let aliased = Rc::ptr_eq(&shared, &alias);
    let deep_equal = deep == *alias;
    let boxed: Box<[String]> = shared[0].keys().cloned().collect();
    let boxed_again = boxed.clone();

    let mut f = Fold::new();
    for m in copy.iter().chain(&deep) {
        f.count(m.len());
        for (k, v) in m {
            f.str(k).count(v.len());
            for x in v {
                f.word(u64::from(*x));
            }
        }
    }
    let summary = format!(
        "{maps} maps of up to {keys} keys, clone equal {equal}, one push unequal {unequal} \
         {order:?}, {untouched} untouched, clone_from equal {reused_equal}, name {name}, rc \
         aliased {aliased} deep equal {deep_equal}, {} boxed keys equal {}",
        boxed.len(),
        boxed == boxed_again
    );
    emit(cx, TAG_CLONE, &summary, &f);
}
