//! Collections: `Vec` and slice methods, `VecDeque`, `BTreeMap`, `BTreeSet`,
//! `BinaryHeap` and `LinkedList` over generated data, and the algorithms
//! people build from them — graph searches, Dijkstra, a k-way merge, an LRU
//! cache. Nearly all of it is generic code monomorphised into this crate, so
//! on the guest it is compiled at the guest's own opt-level, with its overflow
//! checks and debug assertions, rather than taken prebuilt from the sysroot.
//! One section per family of methods, so a mismatch names the family.
//!
//! What the library leaves unspecified never reaches fd 1: which of equal
//! elements an unstable sort, `select_nth_unstable` or a `BinaryHeap` puts
//! first, which of several matches `binary_search` returns, where a `VecDeque`
//! splits into its two slices, and every capacity. Unspecified means free to
//! differ between the host's implementation choices and the guest's, so every
//! unstable operation here runs on elements that are equal only when they are
//! identical, and every heap entry carries a unique tie-break. Stable sorts
//! are the opposite case: their order among ties is the contract, and it is
//! emitted.

use alloc::collections::binary_heap::PeekMut;
use alloc::collections::{BTreeMap, BTreeSet, BinaryHeap, LinkedList, VecDeque};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Reverse;
use core::hint::black_box;
use core::ops::Bound;

use crate::{Ctx, Fault, Rng};

pub const TAGS: (u8, u8) = (0x20, 0x2f);

const TAG_VEC_EDIT: u8 = 0x20;
const TAG_VEC_ARRANGE: u8 = 0x21;
const TAG_SLICE_VIEWS: u8 = 0x22;
const TAG_SORT: u8 = 0x23;
const TAG_SEARCH: u8 = 0x24;
const TAG_DEQUE: u8 = 0x25;
const TAG_MAP: u8 = 0x26;
const TAG_SET: u8 = 0x27;
const TAG_HEAP: u8 = 0x28;
const TAG_LIST: u8 = 0x29;
const TAG_GRAPH: u8 = 0x2a;
const TAG_DIJKSTRA: u8 = 0x2b;
const TAG_LRU: u8 = 0x2c;
const TAG_PAYLOAD: u8 = 0x2d;

const FAULT_INDEX: u8 = 0x20;
const FAULT_REMOVE: u8 = 0x21;
const FAULT_RANGE: u8 = 0x22;
const FAULT_UNWRAP: u8 = 0x23;

pub const FAULTS: &[Fault] = &[
    Fault {
        code: FAULT_INDEX,
        what: "a sorted slice indexed at the partition point of its maximum",
    },
    Fault {
        code: FAULT_REMOVE,
        what: "Vec::remove at an index found before a truncate",
    },
    Fault {
        code: FAULT_RANGE,
        what: "the last chunk of a slice viewed as a full-width window",
    },
    Fault {
        code: FAULT_UNWRAP,
        what: "Option::unwrap on a LinkedList popped once more than it is long",
    },
];

pub fn run(cx: &mut Ctx) {
    let scale = cx.scale() as usize;
    // Two sizes, because the guest's opt-level-0 build prices the families
    // very differently: an element moved through a slice method costs a few
    // hundred cycles, and one sorted or put in a B-tree a few thousand. Most
    // of a section's cost is the number of methods it calls, not the size of
    // their data, so scale 0 — the instruction-by-instruction QEMU
    // differential's run — calls every method once on the smallest data each
    // accepts. From scale 5 on, `n` passes a B-tree leaf's eleven keys, so the
    // maps and sets split, merge and rebalance nodes too.
    let n = 2 + 2 * scale;
    let long = 8 + 8 * scale;
    vec_edit(cx, long);
    vec_arrange(cx, long);
    slice_views(cx, long);
    sorting(cx, n);
    searching(cx, n);
    deque(cx, n);
    map(cx, n);
    sets(cx, n);
    heap(cx, n);
    list(cx, long);
    graph(cx, n);
    dijkstra(cx, n);
    lru(cx, n);
    payload(cx, scale);
}

/// A word-wide FNV-1a fold of fixed-width values: the fingerprint each
/// section here emits. [`crate::Digest`] folds a byte at a time, four 64-bit
/// multiplies per word, and on the guest's opt-level-0 build that costs more
/// than much of the collection work it would fingerprint. One multiply per
/// word is just as much the same on every target, since this too takes no
/// `usize` unwidened.
struct Fold(u64);

impl Fold {
    const fn new() -> Fold {
        Fold(0xcbf2_9ce4_8422_2325)
    }

    fn word(&mut self, v: u32) -> &mut Fold {
        self.0 = (self.0 ^ u64::from(v)).wrapping_mul(0x0000_0100_0000_01b3);
        self
    }

    fn wide(&mut self, v: u64) -> &mut Fold {
        self.word(v as u32).word((v >> 32) as u32)
    }

    /// A length or an index, widened as [`crate::Digest::count`] widens it.
    fn count(&mut self, n: usize) -> &mut Fold {
        self.wide(n as u64)
    }

    fn flag(&mut self, b: bool) -> &mut Fold {
        self.word(u32::from(b))
    }

    /// Every value, then how many, so that two lists folded one after the
    /// other do not fingerprint like their concatenation split elsewhere.
    fn all(&mut self, values: impl IntoIterator<Item = u32>) -> &mut Fold {
        let mut count = 0;
        for v in values {
            self.word(v);
            count += 1;
        }
        self.word(count)
    }

    /// A float's bits, every NaN folded to one, as [`crate::Digest::f64`]
    /// folds them.
    fn float(&mut self, v: f64) -> &mut Fold {
        self.wide(if v.is_nan() {
            0x7ff8_0000_0000_0000
        } else {
            v.to_bits()
        })
    }

    fn bytes(&self) -> [u8; 8] {
        self.0.to_le_bytes()
    }
}

/// `n` values in `0..below`.
fn draw(rng: &mut Rng, n: usize, below: u32) -> Vec<u32> {
    (0..n).map(|_| rng.below(u64::from(below)) as u32).collect()
}

/// `Vec`'s editing methods, each at a position drawn from the data.
fn vec_edit(cx: &mut Ctx, len: usize) {
    let mut f = Fold::new();
    let rng = cx.rng();
    let mut v = draw(rng, len, 1000);

    v.push(rng.next_u32() % 1000);
    f.word(v.pop().unwrap_or(0));
    for k in 0..3 {
        let at = rng.index(v.len() + 1);
        v.insert(at, 1000 + k);
    }
    f.word(v.remove(rng.index(v.len())));
    f.word(v.swap_remove(rng.index(v.len())));
    v.retain(|&x| x % 7 != 3);
    let mut seen = 0;
    v.retain_mut(|x| {
        seen += 1;
        *x = (*x * 3 + seen) % 1009;
        *x % 5 != 0
    });
    f.all(v.iter().copied());

    // Coarse buckets repeat, so the dedups have runs to collapse.
    let mut near: Vec<u32> = v.iter().map(|x| x / 128).collect();
    near.dedup();
    f.all(near.iter().copied());
    near.clone_from(&v);
    near.dedup_by_key(|x| *x / 64);
    near.dedup_by(|later, kept| later.abs_diff(*kept) < 16);
    f.all(near.iter().copied());

    let lo = rng.index(v.len() / 2 + 1);
    let hi = (lo + 1 + rng.index(4)).min(v.len());
    let drained: Vec<u32> = v.drain(lo..hi).collect();
    let at = rng.index(v.len() + 1);
    let end = (at + 2).min(v.len());
    f.all(v.splice(at..end, drained.iter().rev().map(|x| x + 2000)));

    v.truncate(len / 2 + rng.index(len / 2));
    let mut next = 5000;
    v.resize(v.len() + 3, 4242);
    v.resize_with(v.len() + 3, || {
        next += 7;
        next
    });
    v.resize(v.len() - 2, 0);
    f.word(v.pop_if(|x| *x % 2 == 1).unwrap_or(u32::MAX));
    f.all(v.extract_if(.., |x| *x % 3 == 0));
    // A shrink the bump allocator serves as a fresh block and a copy.
    v.shrink_to_fit();
    f.all(v.iter().copied());
    cx.section(TAG_VEC_EDIT, &f.bytes());
}

/// `Vec` rearranged in place — rotations, reversal, swaps, split borrows,
/// `copy_within`, `fill` — then taken apart and put together: `concat`,
/// `join`, `repeat`, `split_off`, `append`, `extend_from_within`.
fn vec_arrange(cx: &mut Ctx, len: usize) {
    let mut f = Fold::new();
    let mut v: Vec<u32> = (0..len as u32).map(|i| i * 10).collect();
    let rng = cx.rng();
    v.rotate_left(rng.index(len));
    v.rotate_right(rng.index(len));
    v[..len / 4].reverse();
    v.reverse();
    let (a, b) = (rng.index(len), rng.index(len));
    v.swap(a, b);
    let (left, right) = v.split_at_mut(rng.index(len + 1));
    for (l, r) in left.iter_mut().rev().zip(right.iter_mut()) {
        core::mem::swap(l, r);
        *l += 1;
    }
    let width = 1 + rng.index(len / 2);
    let (src, dst) = (rng.index(len - width + 1), rng.index(len - width + 1));
    v.copy_within(src..src + width, dst);
    // Every other value is a multiple of 10 or one more, so 7 marks these.
    v[len - 2..].fill(7);
    if let Ok([x, y]) = v.get_disjoint_mut([a, b / 2]) {
        core::mem::swap(x, y);
    }
    f.all(v.iter().copied());

    // The last marker's index, found before a truncate that cuts it off:
    // removing there afterwards is the stale-index bug the fault takes. The
    // swap above moves at most one of the two markers below `len - 2`.
    let marker = v.iter().rposition(|&x| x == 7).unwrap_or(0);
    let keep = v.len() - 3;
    v.truncate(keep);
    let at = if cx.fault(FAULT_REMOVE) {
        marker
    } else {
        marker % keep
    };
    f.word(v.remove(black_box(at)));

    let parts: Vec<Vec<u32>> = v.chunks(1 + len / 3).map(<[u32]>::to_vec).collect();
    f.all(parts.concat());
    f.all(parts.join(&[9, 9][..]));
    let tripled = v[..2].repeat(3);
    f.all(v.iter().rev().step_by(2).copied());
    f.flag(v.contains(&tripled[0]))
        .flag(v.starts_with(&tripled[..1]))
        .flag(v.ends_with(&[7]));

    v.extend_from_within(..2);
    let mut tail = v.split_off(v.len() / 2);
    let mut extra = tripled;
    tail.append(&mut extra);
    v.extend(tail.iter().filter(|x| *x % 2 == 0));
    f.all(v.iter().copied()).count(extra.len());
    cx.section(TAG_VEC_ARRANGE, &f.bytes());
}

/// Slice views: chunks from either end, windows, splits on a predicate,
/// ascending runs with `chunk_by`, fixed-size chunks as arrays.
fn slice_views(cx: &mut Ctx, len: usize) {
    let mut f = Fold::new();
    let rng = cx.rng();
    let data: Vec<u16> = (0..len + 4).map(|_| rng.below(100) as u16).collect();
    let width = 3 + rng.index(3);
    let sum = |s: &[u16]| s.iter().map(|&x| u32::from(x)).sum::<u32>();

    f.all(data.chunks(width).map(sum));
    let exact = data.chunks_exact(width);
    let remainder = exact.remainder();
    f.all(exact.map(|c| u32::from(c[0] ^ c[width - 1])));
    f.all(data.rchunks(width).map(|c| u32::from(c[0])));
    f.all(data.windows(width).map(sum));

    let separator = |x: &u16| x.is_multiple_of(10);
    f.all(data.split(separator).map(|p| p.len() as u32));
    f.all(data.splitn(3, separator).map(sum));
    f.all(
        data.split_inclusive(separator)
            .map(|p| u32::from(p[p.len() - 1])),
    );
    f.all(data.chunk_by(|a, b| a < b).map(|r| r.len() as u32));
    let (quads, tail) = data.as_chunks::<4>();
    f.all(
        quads
            .iter()
            .map(|q| u32::from(q.iter().fold(0u16, |acc, x| acc.rotate_left(3) ^ x))),
    );
    f.count(tail.len());
    if let (Some((first, rest)), Some(pair)) = (data.split_first(), data.last_chunk::<2>()) {
        f.word(u32::from(*first))
            .count(rest.len())
            .word(u32::from(pair[0]) << 16 | u32::from(pair[1]));
    }

    // The last chunk viewed as a full window: right only when `width`
    // divides the length, and the fault takes it regardless.
    let start = data.len() - remainder.len();
    let end = if cx.fault(FAULT_RANGE) {
        start + width
    } else {
        data.len()
    };
    f.all(data[start..black_box(end)].iter().map(|&x| u32::from(x)));
    cx.section(TAG_SLICE_VIEWS, &f.bytes());
}

/// The ids of `(key, id)` records, in their order.
fn ids(records: &[(u8, u16)]) -> impl Iterator<Item = u32> + '_ {
    records.iter().map(|r| u32::from(r.1))
}

/// Stable sorts, whose order among ties is their contract and is emitted, and
/// unstable ones only where that order cannot show.
fn sorting(cx: &mut Ctx, n: usize) {
    let mut f = Fold::new();
    let rng = cx.rng();
    // (key, id): few keys, so many ties; the id is the original position.
    let records: Vec<(u8, u16)> = (0..n).map(|i| (rng.below(4) as u8, i as u16)).collect();

    let mut sorted = records.clone();
    sorted.sort_by_key(|r| r.0);
    f.all(ids(&sorted)).flag(sorted.is_sorted_by_key(|r| r.0));
    // Key mod 3 descending, then the key: ties remain within each key.
    sorted.clone_from(&records);
    sorted.sort_by(|a, b| (b.0 % 3).cmp(&(a.0 % 3)).then(a.0.cmp(&b.0)));
    f.all(ids(&sorted));
    sorted.clone_from(&records);
    sorted.sort_by_cached_key(|r| Reverse(r.0 / 2));
    f.all(ids(&sorted));
    // Unique ids make these total orders, so the unstable sorts are defined.
    sorted.clone_from(&records);
    sorted.sort_unstable_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    f.all(ids(&sorted));
    sorted.clone_from(&records);
    sorted.sort_unstable_by_key(|r| (Reverse(r.1 % 3), r.1));
    f.all(ids(&sorted)).flag(records.is_sorted());

    // Repeated values, equal only when identical: an unstable sort is safe,
    // and must agree with a stable one.
    let values = draw(rng, n, 8);
    let mut unstable = values.clone();
    unstable.sort_unstable();
    let mut stable = values.clone();
    stable.sort();
    f.all(unstable.iter().copied())
        .flag(unstable == stable)
        .flag(stable.is_sorted_by(|a, b| a <= b));
    // What sits at `nth` is defined, and so is the multiset before it; their
    // arrangement is not.
    let nth = rng.index(n);
    stable.clone_from(&values);
    let (below, at, _) = stable.select_nth_unstable(nth);
    f.word(*at).word(below.iter().sum());

    // -0.0 and 0.0 compare equal, so a stable `partial_cmp` sort keeps them
    // in their original order, and `total_cmp` puts -0.0 first. Both go
    // through soft-float comparisons on the guest.
    let floats: Vec<f64> = (0..n)
        .map(|i| match i % 5 {
            0 => -0.0,
            1 => 0.0,
            _ => f64::from(rng.next_u32() as i32 >> 20) / 8.0,
        })
        .collect();
    let mut partial = floats.clone();
    partial.sort_by(|a, b| a.partial_cmp(b).expect("no NaN is drawn"));
    let mut bitwise = floats;
    bitwise.sort_by(f64::total_cmp);
    for x in partial.iter().chain(&bitwise) {
        f.float(*x);
    }
    cx.section(TAG_SORT, &f.bytes());
}

/// Searches. `binary_search` runs over distinct values, because among
/// duplicates which match it returns is unspecified; `partition_point`,
/// `position`, `rposition`, `min_by_key` (the first minimum) and `max_by_key`
/// (the last maximum) are defined on ties and run on them. And arrays.
fn searching(cx: &mut Ctx, n: usize) {
    let mut f = Fold::new();
    let rng = cx.rng();
    let span = 8 * n as u32;
    let mut sorted = draw(rng, n, span);
    sorted.sort_unstable();
    sorted.dedup();
    let records: Vec<(u32, u8)> = sorted.iter().map(|&x| (x, (x % 7) as u8)).collect();

    for i in 0..n {
        let probe = rng.below(u64::from(span)) as u32;
        // Three searches for one answer, a probe each in turn, each held to
        // the partition point.
        let hit = match i % 3 {
            0 => sorted.binary_search(&probe),
            1 => sorted.binary_search_by(|x| x.cmp(&probe)),
            _ => records.binary_search_by_key(&probe, |r| r.0),
        };
        let point = sorted.partition_point(|&x| x < probe);
        match hit {
            Ok(i) => f.flag(true).count(i),
            Err(i) => f.flag(false).count(i),
        };
        f.flag(hit.unwrap_or_else(|i| i) == point);
    }

    let values = draw(rng, n, 4);
    if let (Some((i, _)), Some((j, _))) = (
        values.iter().enumerate().min_by_key(|(_, v)| **v),
        values.iter().enumerate().max_by_key(|(_, v)| **v),
    ) {
        f.count(i).count(j);
    }
    let position = values.iter().position(|&v| v == 2);
    let rposition = values.iter().rposition(|&v| v == 2);
    f.wide(position.map_or(u64::MAX, |i| i as u64))
        .wide(rposition.map_or(u64::MAX, |i| i as u64))
        .word(values.iter().rev().find(|&&v| v > 1).copied().unwrap_or(9))
        .count(
            values
                .iter()
                .skip_while(|&&v| v < 2)
                .take_while(|&&v| v >= 1)
                .count(),
        )
        .count(
            sorted
                .iter()
                .zip(&values)
                .filter(|(a, b)| **a % 4 > **b)
                .count(),
        );

    let last = sorted.len() - 1;
    let picks: [u32; 4] = core::array::from_fn(|i| sorted[i * last / 3]);
    let mut bumped = picks.map(|x| x % 97);
    for x in bumped.each_mut() {
        *x += 1;
    }
    f.all(bumped).all(picks.each_ref().map(|x| x.count_ones()));
    if let Some(head) = sorted.get(..2).and_then(|s| <[u32; 2]>::try_from(s).ok()) {
        f.all(head);
    }

    // The successor of a probe is the element at its partition point, which
    // for the maximum is one past the end. Indexing it unchecked is the fault.
    let fault = cx.fault(FAULT_INDEX);
    let probe = if fault {
        sorted[last]
    } else {
        sorted[last / 2]
    };
    let after = sorted.partition_point(|&x| x <= probe);
    let successor = if fault {
        sorted[black_box(after)]
    } else {
        sorted.get(after).copied().unwrap_or(u32::MAX)
    };
    f.word(successor);
    cx.section(TAG_SEARCH, &f.bytes());
}

/// `VecDeque` grown from both ends of a small buffer, so its contents wrap
/// around it, then edited in place; and the monotonic-deque sliding-window
/// maximum, held to `windows`.
fn deque(cx: &mut Ctx, n: usize) {
    let mut f = Fold::new();
    let rng = cx.rng();
    let mut q: VecDeque<u32> = VecDeque::with_capacity(2);
    for i in 0..2 * n as u32 {
        match rng.below(8) {
            0..=2 => q.push_back(i),
            3..=5 => q.push_front(i),
            6 => {
                f.word(q.pop_front().unwrap_or(u32::MAX));
            }
            _ => {
                f.word(q.pop_back().unwrap_or(u32::MAX));
            }
        }
    }
    let len = q.len();
    q.rotate_left(rng.index(len + 1));
    q.rotate_right(rng.index(len + 1));
    if len >= 2 {
        q.swap(0, len - 1);
    }
    for x in q.iter_mut() {
        *x ^= 0x55;
    }
    let from = rng.index(len + 1);
    let to = from + rng.index(len - from + 1);
    f.all(q.range(from..to).copied());
    q.insert(rng.index(len + 1), 777);
    f.word(q.remove(rng.index(q.len())).unwrap_or(u32::MAX));
    q.retain(|x| x % 11 != 0);
    q.extend([1, 2, 3]);
    let mut back = q.split_off(q.len() / 2);
    back.push_front(999);
    q.append(&mut back);
    f.all(q.drain(1..3));
    q.truncate(n);
    f.word(q.front().copied().unwrap_or(u32::MAX))
        .word(q.back().copied().unwrap_or(u32::MAX))
        .word(q.get(1).copied().unwrap_or(u32::MAX))
        .all(q.iter().rev().copied());

    // Where the contents split between the two slices is the buffer's
    // business; only what they hold together is emitted.
    let (x, y) = q.as_slices();
    f.all(x.iter().chain(y).copied());
    q.make_contiguous().sort_unstable();
    f.count(q.partition_point(|&x| x < 500)).all(Vec::from(q));

    let data = draw(rng, 2 * n, 100);
    let w = 2 + rng.index(3);
    let mut maxima = Vec::with_capacity(data.len());
    let mut window: VecDeque<usize> = VecDeque::new();
    for (i, &x) in data.iter().enumerate() {
        while window.back().is_some_and(|&j| data[j] <= x) {
            window.pop_back();
        }
        window.push_back(i);
        if window[0] + w <= i {
            window.pop_front();
        }
        if i + 1 >= w {
            maxima.push(data[window[0]]);
        }
    }
    let agree = data
        .windows(w)
        .zip(&maxima)
        .all(|(s, m)| s.iter().max() == Some(m));
    f.all(maxima).flag(agree);
    cx.section(TAG_DEQUE, &f.bytes());
}

/// `BTreeMap` over signed keys: every entry-API form, ranges under every kind
/// of bound, `range_mut`, the ends, `split_off`, `append`, `retain`,
/// `extract_if`.
fn map(cx: &mut Ctx, n: usize) {
    let mut f = Fold::new();
    let rng = cx.rng();
    let spread = n as i32;
    let key = |rng: &mut Rng| rng.below(3 * n as u64) as i32 - spread;
    let mut m: BTreeMap<i32, u32> = BTreeMap::new();
    for i in 0..(n + 2) as u32 {
        let k = key(rng);
        match i % 4 {
            0 => *m.entry(k).or_insert(0) += 1,
            1 => {
                m.entry(k).and_modify(|v| *v = *v * 2 % 65_521).or_insert(1);
            }
            2 => {
                m.entry(k).or_insert_with(|| i * 3);
            }
            _ => *m.entry(k).or_default() += i,
        }
    }

    // The signed keys in buckets of a width drawn from the data: `/` and `%`
    // truncate toward zero and `div_euclid` and `rem_euclid` floor, so the
    // two disagree on every negative key the width does not divide.
    let width = 2 + rng.below(3) as i32;
    f.all(m.keys().flat_map(|&k| {
        [
            k / width,
            k % width,
            k.div_euclid(width),
            k.rem_euclid(width),
        ]
        .map(|x| x as u32)
    }));

    let (a, b) = (key(rng), key(rng));
    let (lo, hi) = (a.min(b), a.max(b));
    let values = |entries: &mut dyn Iterator<Item = (&i32, &u32)>| {
        entries.map(|(k, v)| k.unsigned_abs() ^ v).sum::<u32>()
    };
    f.word(values(&mut m.range(lo..hi)))
        .word(values(&mut m.range(..=hi)))
        .word(values(&mut m.range(lo..)))
        .word(values(
            &mut m.range((Bound::Excluded(lo), Bound::Included(hi))),
        ))
        .word(values(
            &mut m
                .range((Bound::Unbounded, Bound::Excluded(hi)))
                .rev()
                .take(2),
        ));
    for (_, v) in m.range_mut(lo..=hi) {
        *v += 1;
    }

    // An i32 key folds as its two's-complement bits, the same on every target.
    for (k, v) in [m.first_key_value(), m.last_key_value()]
        .into_iter()
        .flatten()
    {
        f.word(*k as u32).word(*v);
    }
    for (k, v) in [m.pop_first(), m.pop_last()].into_iter().flatten() {
        f.word(k as u32).word(v);
    }
    if let Some(mut e) = m.first_entry() {
        *e.get_mut() += 100;
    }
    if let Some(e) = m.last_entry() {
        f.word(e.remove());
    }
    f.word(m.insert(lo, 4242).unwrap_or(u32::MAX))
        .word(m.get(&hi).copied().unwrap_or(u32::MAX))
        .word(m.remove(&(lo + 1)).unwrap_or(u32::MAX));
    if let Some(v) = m.get_mut(&0) {
        *v += 1;
    }
    let mut upper = m.split_off(&0);
    upper.retain(|_, v| *v % 2 == 0);
    f.all(
        m.extract_if(.., |k, v| (i64::from(*k) + i64::from(*v)) % 3 == 0)
            .flat_map(|(k, v)| [k as u32, v]),
    );
    m.append(&mut upper);
    for v in m.values_mut() {
        *v %= 1000;
    }
    f.all(m.iter().rev().flat_map(|(k, v)| [*k as u32, *v]));

    // Collected from pairs with repeated keys: the last pair for a key wins.
    let collected: BTreeMap<u8, u32> = (0..n as u32).map(|i| ((i % 5) as u8, i)).collect();
    f.all(collected.into_values());
    cx.section(TAG_MAP, &f.bytes());
}

/// `BTreeSet`: the four set operations as iterators, two as operators, the
/// relations between sets, a range, the ends, and tuple keys under `Reverse`.
fn sets(cx: &mut Ctx, n: usize) {
    let mut f = Fold::new();
    let rng = cx.rng();
    let span = 2 * n as u64;
    let mut a = BTreeSet::new();
    let mut b = BTreeSet::new();
    for _ in 0..n {
        a.insert(rng.below(span) as u32);
        // `insert` answers whether the value is new.
        f.flag(b.insert(rng.below(span) as u32));
    }

    f.all(a.union(&b).copied())
        .all(a.intersection(&b).copied())
        .all(a.difference(&b).copied())
        .all(a.symmetric_difference(&b).copied());
    let union = &a | &b;
    let only_a = &a - &b;
    f.flag(a.is_subset(&union))
        .flag(union.is_superset(&b))
        .flag(only_a.is_disjoint(&b));

    let mid = span as u32 / 2;
    f.count(union.range(mid / 2..mid + mid / 2).count());
    let mut low = union;
    let mut high = low.split_off(&mid);
    f.count(low.len()).count(high.len());
    high.retain(|x| x % 3 != 0);
    low.append(&mut high);
    for x in [low.first(), low.last()].into_iter().flatten() {
        f.word(*x);
    }
    for x in [low.pop_first(), low.pop_last()].into_iter().flatten() {
        f.word(x);
    }
    f.all(low.extract_if(.., |x| x % 4 == 0));
    f.flag(low.insert(mid))
        .flag(low.insert(mid))
        .word(low.take(&mid).unwrap_or(u32::MAX))
        .flag(low.remove(&(mid + 1)))
        .flag(low.contains(&(mid - 1)))
        .all(low.iter().rev().copied());

    // Tuples order lexicographically, and `Reverse` flips the second field.
    let mut pairs: BTreeSet<(u8, Reverse<i16>)> = BTreeSet::new();
    for _ in 0..n / 2 {
        pairs.insert((rng.below(3) as u8, Reverse(rng.below(20) as i16 - 10)));
    }
    f.all(
        pairs
            .iter()
            .map(|&(k, Reverse(v))| u32::from(k) << 16 | u32::from(v as u16)),
    );
    cx.section(TAG_SET, &f.bytes());
}

/// `BinaryHeap` with a unique id in every entry, so no two entries are equal
/// and the pop order is defined; a min-heap through `Reverse`; and a k-way
/// merge of sorted runs driven by one.
fn heap(cx: &mut Ctx, n: usize) {
    let mut f = Fold::new();
    let rng = cx.rng();
    let mut h: BinaryHeap<(u32, u32)> = BinaryHeap::new();
    for id in 0..n as u32 {
        h.push((rng.below(20) as u32, id));
    }
    if let Some(&(p, id)) = h.peek() {
        f.word(p).word(id);
    }
    // Lowering the top through `peek_mut` sifts it down when the guard drops.
    if let Some(mut top) = h.peek_mut() {
        top.0 /= 2;
    }
    if let Some(top) = h.peek_mut() {
        if top.1 % 2 == 0 {
            PeekMut::pop(top);
        }
    }
    // At least one pop: `n` is 2 at scale 0, and `n / 3` would never call it
    // there — on the very inputs the cheapest corpus cases use.
    for _ in 0..1 + n / 3 {
        if let Some((p, id)) = h.pop() {
            f.word(p).word(id);
        }
    }
    h.retain(|&(p, _)| p % 5 != 0);
    let mut other = BinaryHeap::from([(100, 1000), (101, 1001)]);
    h.append(&mut other);
    h.extend([(0, 2000), (19, 2001)]);

    let sorted = h.clone().into_sorted_vec();
    // The heap's own arrangement is unspecified: sorted before it is used.
    let mut raw = h.into_vec();
    raw.sort_unstable();
    f.all(sorted.iter().map(|&(p, id)| (p << 16) | id))
        .flag(raw == sorted);

    let mut min = BinaryHeap::from(sorted.into_iter().map(Reverse).collect::<Vec<_>>());
    if let Some(Reverse((p, id))) = min.pop() {
        f.word(p).word(id);
    }
    // `drain` yields in no particular order, so only its sum is emitted.
    f.word(min.drain().map(|Reverse((p, _))| p).sum());

    let k = 2 + rng.index(2);
    let runs: Vec<Vec<u32>> = (0..k)
        .map(|_| {
            let mut run = draw(rng, n / 2 + 1, 50);
            run.sort();
            run
        })
        .collect();
    // (value, run, index): the run breaks ties between equal values.
    let mut frontier: BinaryHeap<Reverse<(u32, usize, usize)>> = runs
        .iter()
        .enumerate()
        .map(|(i, run)| Reverse((run[0], i, 0)))
        .collect();
    let mut merged = Vec::with_capacity(k * (n / 2 + 1));
    while let Some(Reverse((value, run, at))) = frontier.pop() {
        merged.push(value << 8 | run as u32);
        if let Some(&next) = runs[run].get(at + 1) {
            frontier.push(Reverse((next, run, at + 1)));
        }
    }
    f.flag(merged.is_sorted()).all(merged);
    cx.section(TAG_HEAP, &f.bytes());
}

/// `LinkedList`: both ends, `split_off` and `append` as a rotation, mutation
/// through `iter_mut` and the end references, forward and reverse walks.
fn list(cx: &mut Ctx, len: usize) {
    let mut f = Fold::new();
    let rng = cx.rng();
    let mut head: LinkedList<u32> = LinkedList::new();
    for i in 0..len as u32 {
        if rng.chance(1, 2) {
            head.push_back(i);
        } else {
            head.push_front(i);
        }
    }
    for x in [head.pop_front(), head.pop_back()].into_iter().flatten() {
        f.word(x);
    }
    let mut l = head.split_off(rng.index(head.len() + 1));
    for x in l.iter_mut() {
        *x += 1000;
    }
    l.append(&mut head);
    if let Some(x) = l.front_mut() {
        *x += 1;
    }
    if let Some(x) = l.back_mut() {
        *x *= 2;
    }
    l.extend([7, 8, 9]);
    let evens: LinkedList<u32> = l.iter().filter(|x| *x % 2 == 0).copied().collect();
    f.all(l.iter().copied())
        .all(l.iter().rev().copied())
        .all(evens)
        .flag(l.contains(&1000));

    // Emptied by popping as many times as it is long; the fault pops once
    // more.
    let pops = l.len() + usize::from(cx.fault(FAULT_UNWRAP));
    let mut drained = 0u32;
    for _ in 0..pops {
        drained += l.pop_back().unwrap();
    }
    f.word(drained).flag(l.is_empty());
    cx.section(TAG_LIST, &f.bytes());
}

/// Union-find's root of `v`, halving the path on the way up.
fn find(parent: &mut [u32], mut v: u32) -> u32 {
    while parent[v as usize] != v {
        let grand = parent[parent[v as usize] as usize];
        parent[v as usize] = grand;
        v = grand;
    }
    v
}

/// A DAG under shuffled labels: BFS depths, a DFS preorder, Kahn's
/// topological order with a `BTreeSet` frontier — the smallest ready node
/// first, which makes the order unique — path counts along it, and union-find
/// components over random pairs.
fn graph(cx: &mut Ctx, nodes: usize) {
    let mut f = Fold::new();
    let rng = cx.rng();
    let mut label: Vec<u32> = (0..nodes as u32).collect();
    for i in (1..nodes).rev() {
        label.swap(i, rng.index(i + 1));
    }
    // Edges run from a lower rank to a higher one, so the graph is acyclic;
    // the labels hide the ranks. A repeated edge is a second, parallel one.
    let mut adj: Vec<Vec<u32>> = vec![Vec::new(); nodes];
    let mut edges = 0u32;
    for rank in 0..nodes - 1 {
        for _ in 0..rng.index(3) + 1 {
            let to = rank + 1 + rng.index(nodes - rank - 1);
            adj[label[rank] as usize].push(label[to]);
            edges += 1;
        }
    }

    let root = label[0] as usize;
    let mut depth = vec![u32::MAX; nodes];
    depth[root] = 0;
    let mut queue = VecDeque::from([root]);
    while let Some(u) = queue.pop_front() {
        for &v in &adj[u] {
            if depth[v as usize] == u32::MAX {
                depth[v as usize] = depth[u] + 1;
                queue.push_back(v as usize);
            }
        }
    }
    f.all(depth.iter().copied());

    let mut seen = vec![false; nodes];
    let mut stack = vec![root];
    let mut preorder = Vec::with_capacity(nodes);
    while let Some(u) = stack.pop() {
        if core::mem::replace(&mut seen[u], true) {
            continue;
        }
        preorder.push(u as u32);
        stack.extend(adj[u].iter().rev().map(|&v| v as usize));
    }
    let reached = preorder.len();
    f.all(preorder);

    let mut indegree = vec![0u32; nodes];
    for &v in adj.iter().flatten() {
        indegree[v as usize] += 1;
    }
    let mut ready: BTreeSet<u32> = (0..nodes as u32)
        .filter(|&v| indegree[v as usize] == 0)
        .collect();
    let mut order = Vec::with_capacity(nodes);
    while let Some(u) = ready.pop_first() {
        order.push(u);
        for &v in &adj[u as usize] {
            indegree[v as usize] -= 1;
            if indegree[v as usize] == 0 {
                ready.insert(v);
            }
        }
    }
    f.all(order.iter().copied());

    // Paths from the root, modulo a prime: u64 remainders, which the guest
    // takes from compiler-builtins.
    const PRIME: u64 = 1_000_000_007;
    let mut paths = vec![0u64; nodes];
    paths[root] = 1;
    for &u in &order {
        let here = paths[u as usize];
        for &v in &adj[u as usize] {
            paths[v as usize] = (paths[v as usize] + here) % PRIME;
        }
    }
    let all_paths = paths.iter().fold(0, |acc, p| (acc + p) % PRIME);

    let mut parent: Vec<u32> = (0..nodes as u32).collect();
    let mut size = vec![1u32; nodes];
    for _ in 0..nodes / 2 + 1 {
        let x = find(&mut parent, rng.index(nodes) as u32);
        let y = find(&mut parent, rng.index(nodes) as u32);
        if x != y {
            // By size, and the smaller label on a tie, so the roots are defined.
            let (big, small) = if (size[x as usize], Reverse(x)) > (size[y as usize], Reverse(y)) {
                (x, y)
            } else {
                (y, x)
            };
            parent[small as usize] = big;
            size[big as usize] += size[small as usize];
        }
    }
    let mut sizes: Vec<u32> = (0..nodes as u32)
        .filter(|&v| find(&mut parent, v) == v)
        .map(|v| size[v as usize])
        .collect();
    sizes.sort_unstable_by(|a, b| b.cmp(a));
    f.all(parent);

    let text = format!(
        "edges {edges} reached {reached} paths {all_paths} components {} {:016x}",
        sizes.len(),
        f.all(sizes).0
    );
    cx.section(TAG_GRAPH, text.as_bytes());
}

/// Dijkstra over a random weighted digraph, from node 0. Heap entries are
/// (distance, node), and a node is pushed only at a strictly shorter
/// distance, so no two entries are equal and the settling order is defined.
fn dijkstra(cx: &mut Ctx, nodes: usize) {
    let rng = cx.rng();
    let mut adj: Vec<Vec<(u32, u32)>> = vec![Vec::new(); nodes];
    for out in &mut adj {
        for _ in 0..1 + rng.index(2) {
            out.push((rng.index(nodes) as u32, 1 + rng.below(20) as u32));
        }
    }

    let mut dist = vec![u64::MAX; nodes];
    let mut prev = vec![u32::MAX; nodes];
    dist[0] = 0;
    let mut heap = BinaryHeap::from([Reverse((0u64, 0u32))]);
    let mut settled = 0u32;
    while let Some(Reverse((du, u))) = heap.pop() {
        if du > dist[u as usize] {
            continue;
        }
        settled += 1;
        for &(v, w) in &adj[u as usize] {
            let alt = du + u64::from(w);
            if alt < dist[v as usize] {
                dist[v as usize] = alt;
                prev[v as usize] = u;
                heap.push(Reverse((alt, v)));
            }
        }
    }

    // `max_by_key` keeps the last of equal distances.
    let (far, far_dist) = dist
        .iter()
        .enumerate()
        .filter(|(_, x)| **x != u64::MAX)
        .max_by_key(|(_, x)| **x)
        .map_or((0, 0), |(i, x)| (i as u32, *x));
    let mut path = vec![far];
    while let Some(&hop) = path.last() {
        match prev[hop as usize] {
            u32::MAX => break,
            p => path.push(p),
        }
    }
    path.reverse();

    let mut f = Fold::new();
    for (x, p) in dist.iter().zip(&prev) {
        f.wide(*x).word(*p);
    }
    let text = format!(
        "settled {settled} farthest {far} at {far_dist} hops {} {:016x}",
        path.len() - 1,
        f.all(path).0
    );
    cx.section(TAG_DIJKSTRA, text.as_bytes());
}

/// An LRU cache: a `VecDeque` of keys in recency order beside a `BTreeMap`
/// of use counts, over a skewed access stream.
fn lru(cx: &mut Ctx, n: usize) {
    let mut f = Fold::new();
    let rng = cx.rng();
    let capacity = 3 + rng.index(3);
    let mut recency: VecDeque<u32> = VecDeque::with_capacity(capacity);
    let mut cache: BTreeMap<u32, u32> = BTreeMap::new();
    let (mut hits, mut evictions) = (0u32, 0u32);
    for step in 0..2 * n as u32 + 2 {
        // Mostly a small hot set, sometimes anything.
        let key = if rng.chance(3, 4) {
            rng.below(5)
        } else {
            rng.below(24)
        } as u32;
        if let Some(uses) = cache.get_mut(&key) {
            hits += 1;
            *uses += 1;
            let at = recency
                .iter()
                .position(|&k| k == key)
                .expect("a cached key has a recency");
            recency.remove(at);
            recency.push_back(key);
        } else {
            if cache.len() == capacity {
                let oldest = recency.pop_front().expect("a full cache has an oldest key");
                let uses = cache.remove(&oldest).expect("the oldest key is cached");
                f.word(oldest).word(uses).word(step);
                evictions += 1;
            }
            cache.insert(key, 1);
            recency.push_back(key);
        }
    }
    f.all(recency.iter().flat_map(|k| [*k, cache[k]]));
    let text = format!(
        "capacity {capacity} hits {hits} evictions {evictions} {:016x}",
        f.0
    );
    cx.section(TAG_LRU, text.as_bytes());
}

/// The payload as given, bytes that may not be text: words counted in a map
/// keyed by borrowed slices, ranked under a total order, and runs of one
/// byte.
fn payload(cx: &mut Ctx, scale: usize) {
    let mut f = Fold::new();
    let payload = cx.payload();
    let text = &payload[..payload.len().min(24 + 16 * scale)];

    let mut words: BTreeMap<&[u8], u32> = BTreeMap::new();
    for word in text
        .split(|b| b.is_ascii_whitespace() || b.is_ascii_punctuation())
        .filter(|w| !w.is_empty())
    {
        *words.entry(word).or_default() += 1;
    }
    // Count descending, then the word: distinct words make it a total order.
    let mut ranked: Vec<(&[u8], u32)> = words.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    for (w, c) in &ranked {
        f.all(w.iter().map(|&b| u32::from(b))).word(*c);
    }
    let longest_run = text.chunk_by(|a, b| a == b).map(<[u8]>::len).max();
    f.count(longest_run.unwrap_or(0));
    // The top word, escaped: arbitrary bytes, printed the same everywhere.
    let top: String = ranked.first().map_or(String::new(), |(w, c)| {
        format!("{}x{c}", w[..w.len().min(12)].escape_ascii())
    });
    let text = format!("words {} top {top} {:016x}", ranked.len(), f.0);
    cx.section(TAG_PAYLOAD, text.as_bytes());
}
