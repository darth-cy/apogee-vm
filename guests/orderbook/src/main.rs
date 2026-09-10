#![no_std]
#![no_main]
//! A uniform-price call auction. One batch of limit orders goes in; the single
//! clearing price that maximises matched volume comes out, with the volume it
//! matches and how many orders on each side it fills.
//!
//! # What this is a fixture for
//!
//! **The heap and the collections.** Nothing else in `guests/` leans on
//! `alloc` for more than a byte buffer. This one runs `Vec`, `BTreeMap`, a
//! sort and a few iterator chains over a batch of up to 256 orders, on an
//! allocator whose `dealloc` does nothing — so its peak footprint is the *sum*
//! of every allocation it ever made, not the most it ever held at once. That
//! sum is a few tens of kilobytes against the just-under-256-MiB window
//! `link.ld` reserves, not quite four orders of magnitude of headroom. It
//! grows linearly with the batch and the 256-order cap is the only thing
//! holding it down, so the allocator's ceiling check stays out of reach here
//! while staying reachable in principle: uncapped, a large enough batch finds
//! it, and exits 71 rather than running the heap into the stack.
//!
//! **Hint-then-verify.** This is the reference demonstration of the fd 3 rule.
//! Sorting the batch costs O(n log n); checking that a claimed permutation is
//! already sorted costs O(n), so the prover's advice is worth taking — but
//! only once it has been checked, because the prover chooses it and nothing
//! binds it. Every check below runs before a single advised byte reaches the
//! auction, and if any of them fails the guest sorts the batch itself. The two
//! paths commit identical bytes, which is the whole point; the one thing that
//! differs between them is a line on fd 2.
//!
//! # fd 0 — the public input, little-endian throughout
//!
//! ```text
//! 0x00  u32  n_orders          at most 256
//! ```
//!
//! then `n_orders` records of 20 bytes each:
//!
//! ```text
//! +0x00 u32  side              0 = bid (buy), 1 = ask (sell)
//! +0x04 u64  price             in ticks
//! +0x0c u64  qty
//! ```
//!
//! A record whose side is neither 0 nor 1, or whose quantity is zero, is
//! *rejected*: it is counted on fd 1 and takes no other part in the auction.
//! It still holds its place in the sort, so that the permutation on fd 3 is a
//! permutation of the whole batch and not of some filtered subset of it.
//!
//! # fd 1 — the public output, one 28-byte record
//!
//! ```text
//! 0x00  u64  clearing_price    0 when nothing matches
//! 0x08  u64  matched_qty       saturating; see `commit_result`
//! 0x10  u32  bids_filled       resting bids at or above the clearing price
//! 0x14  u32  asks_filled       resting asks at or below it
//! 0x18  u32  orders_rejected   malformed side, or zero quantity
//! ```
//!
//! # fd 3 — the prover's advice
//!
//! ```text
//! 0x00  u32  n                 must equal n_orders
//! ```
//!
//! then `n` little-endian `u32` indices, claiming to be the permutation that
//! sorts the batch under [`key`]. Three checks decide whether that claim is
//! taken, and they are all-or-nothing: the advice is used entire or discarded
//! entire, never patched up. See [`advised_permutation`].

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

guest_sdk::entry!(main);

fn main() {
    let orders = read_orders();
    guest_sdk::log(b"orderbook: orders=");
    log_u32(orders.len() as u32);
    guest_sdk::log(b"\n");

    // fd 2 is the only stream that may mention the hint. Which path produced
    // the sequence is not a fact about the auction — it is a fact about the
    // prover — and a flag saying "the advice was good" on fd 1 would be a bit
    // the prover gets to choose, which is exactly what the fd 3 rule forbids.
    let sorted = match advised_permutation(&orders) {
        Ok(advised) => {
            guest_sdk::log(b"orderbook: advice=verified\n");
            advised
        }
        Err(reason) => {
            guest_sdk::log(b"orderbook: advice=rejected reason=");
            guest_sdk::log(reason.as_bytes());
            guest_sdk::log(b"\n");
            sort_orders(&orders)
        }
    };

    // The linchpin. Both paths converge here, and one linear pass is what makes
    // them interchangeable: everything downstream reads sortedness as a
    // precondition, so if the checked-advice path and the sort-it-yourself path
    // could ever disagree about it, this is where that shows up as a panic
    // rather than as a different number on fd 1.
    assert!(
        is_key_sorted(&orders, &sorted),
        "orderbook: the working sequence is not in key order"
    );

    let mut levels = aggregate(&orders, &sorted);
    accumulate_curves(&mut levels);
    let (clearing_price, matched) = clearing(&levels);

    // No clearing price means no fills. Counting against the sentinel would
    // report every bid as filled, since every price is at or above zero.
    let (bids_filled, asks_filled) = if matched == 0 {
        (0, 0)
    } else {
        count_fills(&orders, &sorted, clearing_price)
    };

    let orders_rejected = orders.iter().filter(|order| !order.is_valid()).count() as u32;
    guest_sdk::log(b"orderbook: rejected=");
    log_u32(orders_rejected);
    guest_sdk::log(b"\n");

    commit_result(
        clearing_price,
        matched,
        bids_filled,
        asks_filled,
        orders_rejected,
    );
}

// ---------------------------------------------------------------------------
// The wire format
// ---------------------------------------------------------------------------

/// The batch cap. It is what makes every length arithmetic below fit in a
/// `usize` without a checked form, and what keeps the heap footprint bounded.
const MAX_ORDERS: usize = 256;

/// One fd 0 order record: `u32` side, `u64` price, `u64` quantity.
const RECORD_BYTES: usize = 20;

/// One fd 3 permutation entry.
const INDEX_BYTES: usize = 4;

const SIDE_BID: u32 = 0;
const SIDE_ASK: u32 = 1;

/// A limit order exactly as fd 0 gave it, side included in its raw form.
///
/// The side is kept as the `u32` that was read rather than narrowed to an
/// enum, because a malformed side still has to sort somewhere: the advice on
/// fd 3 permutes the whole batch, so [`key`] has to be defined on every record
/// the batch contains, valid or not.
struct Order {
    side: u32,
    price: u64,
    qty: u64,
}

impl Order {
    /// Whether this order takes part in the auction at all.
    ///
    /// A zero quantity is rejected rather than tolerated as a no-op, because an
    /// order for nothing at a price still moves the fill *counts* if it is left
    /// in, and those counts are committed.
    fn is_valid(&self) -> bool {
        matches!(self.side, SIDE_BID | SIDE_ASK) && self.qty > 0
    }
}

/// Read the whole batch from fd 0.
///
/// The count is checked against the cap *before* it sizes the body buffer, so
/// the one multiplication here cannot overflow and the one allocation here has
/// a bound that comes from this file rather than from the input.
fn read_orders() -> Vec<Order> {
    let mut header = [0u8; 4];
    assert_eq!(
        guest_sdk::read_input(&mut header),
        header.len(),
        "orderbook: fd 0 must open with a u32 order count"
    );
    let declared = u32::from_le_bytes(header) as usize;
    assert!(
        declared <= MAX_ORDERS,
        "orderbook: the batch is capped at {MAX_ORDERS} orders"
    );

    // A short read here is the end of the stream, and the end of the stream
    // before the declared count is a truncated batch — proceeding would prove
    // something about the zeroes left in the tail of this buffer.
    let mut body = vec![0u8; declared * RECORD_BYTES];
    assert_eq!(
        guest_sdk::read_input(&mut body),
        body.len(),
        "orderbook: fd 0 ended before the declared orders did"
    );

    body.chunks_exact(RECORD_BYTES).map(parse_order).collect()
}

/// Decode one 20-byte fd 0 record.
fn parse_order(bytes: &[u8]) -> Order {
    Order {
        side: u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .expect("an order record opens with four bytes"),
        ),
        price: u64::from_le_bytes(
            bytes[4..12]
                .try_into()
                .expect("an order record carries eight price bytes"),
        ),
        qty: u64::from_le_bytes(
            bytes[12..20]
                .try_into()
                .expect("an order record carries eight quantity bytes"),
        ),
    }
}

/// Write the result to fd 1 as one contiguous 28-byte record.
///
/// One `commit` rather than five, so the journal cannot be left half-written by
/// an executor that fails between fields, and so the record's layout is visible
/// in one place next to the module doc that specifies it.
///
/// `matched` saturates on the way down to a `u64`. It is accumulated in `u128`
/// so that the comparisons that pick the clearing price are exact, and only the
/// winning figure is narrowed; reaching the clamp needs more than `2^64` ticks
/// resting on *both* sides at once, which no honest batch of 256 orders has.
/// A defined clamp beats a panic there: the input is well-formed, so it
/// deserves an answer rather than a failed execution.
fn commit_result(
    clearing_price: u64,
    matched: u128,
    bids_filled: u32,
    asks_filled: u32,
    orders_rejected: u32,
) {
    let matched_qty = u64::try_from(matched).unwrap_or(u64::MAX);
    let mut record = [0u8; 28];
    record[0..8].copy_from_slice(&clearing_price.to_le_bytes());
    record[8..16].copy_from_slice(&matched_qty.to_le_bytes());
    record[16..20].copy_from_slice(&bids_filled.to_le_bytes());
    record[20..24].copy_from_slice(&asks_filled.to_le_bytes());
    record[24..28].copy_from_slice(&orders_rejected.to_le_bytes());
    guest_sdk::commit(&record);
}

// ---------------------------------------------------------------------------
// The total order
// ---------------------------------------------------------------------------

/// The sort key: `(side, rank, index)`.
///
/// `rank` is the price for an ask and `u64::MAX - price` for a bid, so that
/// ascending rank is descending price on the bid side. A bid's best price is
/// its highest and an ask's is its lowest; inverting one of the two lets a
/// single ascending sort put both sides best-first, which is what makes the
/// fills a prefix of each block later on.
///
/// The trailing index breaks every remaining tie, so the order is total: no two
/// records compare equal, the sorted sequence is unique, and the sort is a
/// function of the input rather than of the algorithm that produced it. That is
/// what lets a checked permutation from fd 3 stand in for a sort done here.
///
/// Written as a function returning a tuple, and compared as a tuple, rather
/// than as a derived `Ord` on `Order`: a derive would put the ordering in the
/// field declaration order, where a later field reshuffle changes the committed
/// answer without touching a line that looks like it decides anything.
fn key(order: &Order, index: u32) -> (u32, u64, u32) {
    // `u64::MAX - price` cannot underflow: a `u64` price is at most `u64::MAX`.
    let rank = if order.side == SIDE_BID {
        u64::MAX - order.price
    } else {
        order.price
    };
    (order.side, rank, index)
}

/// Whether `perm` is a batch-length list of in-range indices whose keys never
/// decrease.
///
/// Total on its arguments — `get` rather than indexing — because it is also the
/// gate on unverified advice, where an index need not be in range at all. It
/// says nothing about duplicates, and cannot: two copies of one index are in
/// key order with themselves, so the bitset in [`advised_permutation`] is what
/// rules them out, and only with that in hand does "sorted" mean "the sorted
/// permutation".
fn is_key_sorted(orders: &[Order], perm: &[u32]) -> bool {
    if perm.len() != orders.len() {
        return false;
    }
    let mut previous: Option<(u32, u64, u32)> = None;
    for &index in perm {
        let Some(order) = orders.get(index as usize) else {
            return false;
        };
        let current = key(order, index);
        if previous.is_some_and(|earlier| current < earlier) {
            return false;
        }
        previous = Some(current);
    }
    true
}

/// Sort the batch here, for when the advice on fd 3 is not usable.
///
/// `sort_unstable` is the right choice and not a compromise: [`key`] admits no
/// ties, so stability has nothing to preserve, and the result is the one
/// sequence the total order allows however the pivots fall.
fn sort_orders(orders: &[Order]) -> Vec<u32> {
    let mut perm: Vec<u32> = (0..orders.len() as u32).collect();
    perm.sort_unstable_by_key(|&index| key(&orders[index as usize], index));
    perm
}

// ---------------------------------------------------------------------------
// The prover's advice
// ---------------------------------------------------------------------------

/// Read fd 3 and either return a permutation that has passed every check, or
/// say which check turned it down.
///
/// The three checks are the ones the fd 3 rule demands, and they are cheaper
/// together than the sort they replace: the range and duplicate checks are one
/// pass over a bitset this function builds itself — one `Vec<u64>` and one
/// shift per index, where a set would be a tree of allocations — and the order
/// check is one more pass. O(n) against O(n log n), which is why the advice is
/// worth asking for.
///
/// Nothing here is patched up. A permutation that is right except for one entry
/// is not a permutation that is nearly right, it is a permutation the prover
/// chose, so a failure at any point discards the whole of fd 3 and the caller
/// sorts for itself. The discarded `Vec`s stay resident — `dealloc` does
/// nothing — so the fallback path is also the one that allocates most, and it
/// is the path the heap footprint above is measured on.
fn advised_permutation(orders: &[Order]) -> Result<Vec<u32>, &'static str> {
    let mut header = [0u8; 4];
    if guest_sdk::hint(&mut header) != header.len() {
        return Err("fd 3 carries no advice");
    }

    // Checked against fd 0 before it is allowed to size anything. The prover
    // picks this number, and an allocation sized by it is an allocation the
    // prover picks — which on a bump allocator that never gives anything back
    // is a denial of service dressed as a length field.
    if u32::from_le_bytes(header) as usize != orders.len() {
        return Err("the advised length disagrees with fd 0");
    }

    let mut body = vec![0u8; orders.len() * INDEX_BYTES];
    if guest_sdk::hint(&mut body) != body.len() {
        return Err("the advised permutation is truncated");
    }
    let perm: Vec<u32> = body
        .chunks_exact(INDEX_BYTES)
        .map(|word| {
            u32::from_le_bytes(
                word.try_into()
                    .expect("chunks_exact yields four bytes at a time"),
            )
        })
        .collect();

    // Checks one and two share a pass, because the range check has to come
    // first in any case: `seen` is sized to the batch, so an index past the end
    // of the batch has no bit to test.
    const BITSET_BITS: usize = u64::BITS as usize;
    let mut seen: Vec<u64> = vec![0u64; orders.len().div_ceil(BITSET_BITS)];
    for &index in &perm {
        let index = index as usize;
        if index >= orders.len() {
            return Err("an advised index is out of range");
        }
        let word = index / BITSET_BITS;
        let mask = 1u64 << (index % BITSET_BITS);
        if seen[word] & mask != 0 {
            return Err("an advised index appears twice");
        }
        seen[word] |= mask;
    }

    // Check three. With the first two passed, `perm` holds `n` distinct indices
    // below `n`, so it is a permutation; this says it is the sorting one.
    if !is_key_sorted(orders, &perm) {
        return Err("the advised sequence is not in key order");
    }

    Ok(perm)
}

// ---------------------------------------------------------------------------
// The auction
// ---------------------------------------------------------------------------

/// One price level: what rests there on each side, and what the two cumulative
/// curves are worth at that price once [`accumulate_curves`] has run.
///
/// The four figures are `u128` for a reason that is arithmetic rather than
/// ambition. A quantity is a `u64` and there are at most 256 of them, so any
/// total is under `256 * 2^64 = 2^72` — which a `u128` holds exactly and a
/// `u64` does not. Exactness matters here and not only at the boundary: the
/// clearing price is chosen by *comparing* matched volumes, and saturating
/// `u64` totals would compare equal where the true figures differ and hand the
/// answer to the tie-break instead.
#[derive(Default)]
struct Level {
    bid_qty: u128,
    ask_qty: u128,
    demand: u128,
    supply: u128,
}

/// Fold the batch into one entry per price.
///
/// This is the first of the three things sortedness buys. All the orders that
/// share a side and a price are contiguous in a sequence sorted by [`key`], so
/// each price level is exactly one run: the map is touched once per level
/// rather than once per order, and the `assert` on an already-filled slot is
/// the invariant that says so out loud.
///
/// Rejected orders are skipped, but they are skipped *within* a run rather than
/// filtered out beforehand, which is what keeps the indices in `sorted` lined
/// up with the batch fd 0 delivered. Those indices are used to subscript the
/// batch directly, which [`is_key_sorted`] has already established is in range.
fn aggregate(orders: &[Order], sorted: &[u32]) -> BTreeMap<u64, Level> {
    let mut levels: BTreeMap<u64, Level> = BTreeMap::new();
    let mut start = 0;
    while start < sorted.len() {
        let head = &orders[sorted[start] as usize];
        let mut total: u128 = 0;
        let mut end = start;
        while end < sorted.len() {
            let order = &orders[sorted[end] as usize];
            if order.side != head.side || order.price != head.price {
                break;
            }
            // Under 2^72 across the whole batch, so the accumulator cannot
            // overflow and needs no checked form.
            if order.is_valid() {
                total += u128::from(order.qty);
            }
            end += 1;
        }

        if total > 0 {
            // A run with a positive total holds at least one valid order, and
            // every record in a run shares a side, so this side is a bid or an
            // ask and nothing else.
            assert!(
                head.side == SIDE_BID || head.side == SIDE_ASK,
                "orderbook: a rejected side accumulated a quantity"
            );
            let level = levels.entry(head.price).or_default();
            let slot = if head.side == SIDE_BID {
                &mut level.bid_qty
            } else {
                &mut level.ask_qty
            };
            assert_eq!(
                *slot, 0,
                "orderbook: a price level was aggregated more than once"
            );
            *slot = total;
        }

        start = end;
    }
    levels
}

/// Turn the resting quantities into the demand and supply curves.
///
/// `supply(p)` is the quantity of asks priced at or below `p`, so it is a
/// prefix sum over the map's ascending order; `demand(p)` is the quantity of
/// bids priced at or above `p`, so it is the same sum taken backwards. Both are
/// bounded by the batch total, under `2^72`, so neither running figure can
/// overflow its `u128`.
fn accumulate_curves(levels: &mut BTreeMap<u64, Level>) {
    let mut running: u128 = 0;
    for level in levels.values_mut() {
        running += level.ask_qty;
        level.supply = running;
    }

    let mut running: u128 = 0;
    for level in levels.values_mut().rev() {
        running += level.bid_qty;
        level.demand = running;
    }
}

/// Pick the clearing price, and return it with the volume it matches.
///
/// Only a price that some order actually named can be optimal: between two
/// adjacent quoted prices neither curve moves, so matched volume is flat there
/// and the lower end of the interval is already a candidate. The map's keys are
/// therefore the whole search space.
///
/// The tie-break falls out of the traversal rather than being applied to it.
/// The map iterates ascending and only a *strictly* greater volume displaces
/// the incumbent, so of the prices that match the most volume the lowest is the
/// one that survives — which is what makes the answer unique, and unique is
/// what a committed value has to be.
///
/// Nothing matching leaves the price at zero, which is the fd 1 sentinel. That
/// collides with a genuine clearing price of zero only in appearance: the
/// sentinel case carries a matched volume of zero, and a real clearing price of
/// zero carries a positive one.
fn clearing(levels: &BTreeMap<u64, Level>) -> (u64, u128) {
    let mut best_price = 0u64;
    let mut best_matched = 0u128;
    for (&price, level) in levels {
        let matched = level.demand.min(level.supply);
        if matched > best_matched {
            best_matched = matched;
            best_price = price;
        }
    }
    (best_price, best_matched)
}

/// Count the orders each side fills at `clearing_price`.
///
/// The other two things sortedness buys. The sequence is ordered on side first,
/// so the bids are a leading block and the asks the block after them, and
/// `partition_point` finds both boundaries by bisection instead of by a scan.
/// Within a block the price moves monotonically away from the money, so the
/// fills are a prefix of it: the walk stops at the first order that is out of
/// the money rather than testing the rest, and the assertion in `main` is what
/// licenses that stop.
///
/// Rejected orders are counted by neither side. An order that is not in the
/// book cannot be filled by it, and the fill counts are committed.
fn count_fills(orders: &[Order], sorted: &[u32], clearing_price: u64) -> (u32, u32) {
    let bid_block = sorted.partition_point(|&index| orders[index as usize].side == SIDE_BID);
    let (bids, rest) = sorted.split_at(bid_block);
    let ask_block = rest.partition_point(|&index| orders[index as usize].side == SIDE_ASK);
    let asks = &rest[..ask_block];

    // At most `MAX_ORDERS` on either side, so the counters stay far inside a
    // `u32` and the increments need no checked form.
    let mut bids_filled = 0u32;
    for &index in bids {
        let order = &orders[index as usize];
        if order.price < clearing_price {
            break;
        }
        if order.is_valid() {
            bids_filled += 1;
        }
    }

    let mut asks_filled = 0u32;
    for &index in asks {
        let order = &orders[index as usize];
        if order.price > clearing_price {
            break;
        }
        if order.is_valid() {
            asks_filled += 1;
        }
    }

    (bids_filled, asks_filled)
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

/// Write `value` to fd 2 in decimal.
///
/// Hand-rolled rather than formatted, so that a diagnostic line costs no
/// allocation on an allocator that never gives anything back, and so that the
/// only division in this guest is the 32-bit one the target has an instruction
/// for.
fn log_u32(value: u32) {
    // `u32::MAX` is ten digits and the loop writes at least one, so the cursor
    // lands inside the buffer and never runs off the front of it.
    let mut digits = [0u8; 10];
    let mut cursor = digits.len();
    let mut rest = value;
    loop {
        cursor -= 1;
        digits[cursor] = b'0' + (rest % 10) as u8;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    guest_sdk::log(&digits[cursor..]);
}
