#![no_std]
#![no_main]
//! A marketplace's listings table, summarized by its Merkle root, and a batch of
//! operations against it: list an item, reprice it, buy from it, delist it.
//!
//! # What this is a fixture for
//!
//! **A database a proof follows by its root.** The table is `2^DEPTH` listing
//! slots, the leaves of a fixed-depth binary tree whose every node is
//! [`poseidon2_compress`] of its children, over [`Digest`]s, whose lanes are
//! each below `p`. The public input carries the root before the batch and the
//! batch; the advice carries, for each run of ops on one slot, the slot's
//! listing and its `DEPTH` siblings, a Merkle proof. Nothing advised is
//! trusted: the guest rebuilds the root from the proof before it reads the
//! listing, panics where the two differ, applies the run's ops to the listing
//! it holds, and builds the next root from the listing they leave, along the
//! same path. Each root is one [`merkle_root`] call, the Merkle path
//! precompile, over the advised siblings in place. A verifier holding the
//! roots follows the whole table without anyone publishing it.
//!
//! **One proof a run.** A run is a stretch of consecutive ops on one slot. No
//! other slot moves while it lasts, so the slot's siblings hold; each listing
//! it passes through after the one its proof opens is the guest's own
//! arithmetic; and no root but the batch's first and last is published. So a
//! run opens its proof once and writes one root back, two `merkle_root` calls
//! and two leaf permutations however many ops it holds, half that where it
//! leaves its listing as it found it.
//!
//! **The order is the sequencer's.** Grouping a listing's ops together is a
//! sequencing policy upstream of the guest, and the order it chooses becomes
//! part of the batch: the guest proves the batch in that order, opening a proof
//! wherever an op's slot is not the one before's, and never sorts. It presumes
//! each listing's ops gathered, one proof a listing; a batch in any other order
//! is as valid, at a proof a run, at worst one an op. Regrouping a batch can
//! change its result, not only its cost. Purchases in one currency on two slots
//! compete for its tally's room below `2^256`, and the one refused leaves its
//! stock as it was, so which succeeds, and the root after, follow the order; so
//! does the order of the journal's tallies, each currency's place its first
//! purchase's.
//!
//! A price is a [`U256`], an ERC-20 amount's width, in its listing's currency:
//! an ERC-20 contract's address, or the zero address for the chain's native
//! currency. A listing and a reprice each set both, a quote. A purchase costs
//! `price · quantity` and pays `cost · fee_bps / 10_000` in fees, the
//! `MUL_DIV_U256` precompile, both in that currency; the journal tallies them
//! per currency, as no total across two tokens means anything.
//!
//! # The leaf
//!
//! A listing is 76 bytes, packed seven to a lane into eleven lanes below
//! `2^56 < p`, so the packing is injective. Its leaf is one permutation of those
//! lanes, four zeros and the tag 1, `compress(lanes 0..8, [lanes 8..11, 0, 0,
//! 0, 0, 1])`, the tag naming this encoding of a listing. An empty slot holds
//! the all-zero listing.
//!
//! ```text
//! listing    0..8    seller    u64; 0 only in an empty slot
//!            8..16   item      u64
//!           16..48   price     U256 LE
//!           48..56   stock     u64
//!           56..76   currency  20 bytes: an ERC-20 contract's address; 0, native
//! ```
//!
//! The tag does not keep a leaf's preimage apart from a node's: a node
//! compresses any two digests, and a leaf's sixteen lanes are two digests as
//! well. The depth does. Every proof is `DEPTH` siblings, so a listing's leaf
//! is always `DEPTH` compressions below the root, where the table's leaves are
//! and none of its nodes. A tree whose proofs varied in length would need its
//! leaves hashed apart from its nodes.
//!
//! # The public input
//!
//! ```text
//! header     0..64   root      8 lanes, u64 LE, each below p: the table before the batch
//!           64..68   fee_bps   u32, at most 1000
//!           68..72   n_ops     u32, at most MAX_OPS
//! op         0..4    kind      u32: 0 list, 1 reprice, 2 buy, 3 delist
//!            4..8    slot      u32, below 2^DEPTH
//!            8..16   account   u64: the seller; a buy's buyer
//!           16..24   item      u64: a list's
//!           24..56   price     U256 LE: a list's or a reprice's
//!           56..64   quantity  u64: a list's stock, a buy's count
//!           64..84   currency  20 bytes: a list's or a reprice's, the price's
//! ```
//!
//! The input is the header and its `n_ops` ops and nothing more, so no byte of
//! the statement goes unread.
//!
//! # The advice
//!
//! For each run, in order: its slot's listing, then the slot's `DEPTH` siblings
//! from the leaf up, 64 bytes each, a digest, under the root the runs before it
//! left. The precompile reads each sibling's lanes in place, mod `p`: a
//! sibling's encoding is the prover's, and no root depends on it.
//!
//! # The journal
//!
//! ```text
//!            0..64   the root before the batch
//!           64..128  the root after it
//!          128..132  applied   u32
//!          132..136  rejected  u32
//!          136..140  k         u32: the currencies with a purchase
//! tally      0..20   currency  in the order of the currency's first purchase
//!           20..52   volume    U256: its purchases' cost
//!           52..84   fees      U256: its purchases' fees
//! ```
//!
//! An op that breaks a rule — a slot already listed, an account not the
//! listing's seller, a purchase past the stock or by the seller, a tally past
//! `2^256` — is rejected and counted, and leaves the table as it was. A
//! malformed batch, an input root with a lane at or above `p`, and a proof that
//! does not open the table, panic.

use constants::guest_memory;
use guest_sdk::{merkle_root, poseidon2_compress, Digest, U256};

guest_sdk::entry!(main);

/// The tree's depth: `2^20` slots.
const DEPTH: usize = 20;
const LISTING: usize = 76;
/// The lanes a listing packs into, seven bytes each.
const LANES: usize = LISTING.div_ceil(7);
const HEADER: usize = 72;
const OP: usize = 84;
const JOURNAL_HEADER: usize = 140;
const TALLY: usize = 84;
const PAYLOAD: usize = guest_memory::PUBLIC_PAYLOAD_BYTES as usize;
/// As many ops as fit the public input beside its header, and their tallies
/// the journal beside its own: each purchase may be in a currency of its own.
const MAX_OPS: usize = {
    let (input, journal) = ((PAYLOAD - HEADER) / OP, (PAYLOAD - JOURNAL_HEADER) / TALLY);
    if input < journal {
        input
    } else {
        journal
    }
};
const MAX_FEE_BPS: u32 = 1_000;

/// An ERC-20 contract's address, what a price is in; zero, the native currency.
type Currency = [u8; 20];

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Listing {
    seller: u64,
    item: u64,
    price: U256,
    stock: u64,
    currency: Currency,
}

impl Listing {
    fn decode(b: &[u8]) -> Listing {
        Listing {
            seller: u64_at(b, 0),
            item: u64_at(b, 8),
            price: u256_at(b, 16),
            stock: u64_at(b, 48),
            currency: b[56..76].try_into().expect("20 bytes"),
        }
    }

    fn leaf(&self) -> Digest {
        let mut bytes = [0u8; 7 * LANES];
        bytes[..8].copy_from_slice(&self.seller.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.item.to_le_bytes());
        bytes[16..48].copy_from_slice(&self.price.to_le_bytes());
        bytes[48..56].copy_from_slice(&self.stock.to_le_bytes());
        bytes[56..LISTING].copy_from_slice(&self.currency);
        let mut lanes = [0u64; 16];
        for (i, lane) in lanes.iter_mut().take(LANES).enumerate() {
            let mut b = [0u8; 8];
            b[..7].copy_from_slice(&bytes[7 * i..7 * i + 7]);
            *lane = u64::from_le_bytes(b);
        }
        lanes[15] = 1;
        let half = |at: usize| {
            let half: [u64; 8] = lanes[at..at + 8].try_into().expect("eight lanes");
            Digest::new(half).expect("seven bytes are below p")
        };
        poseidon2_compress(&half(0), &half(8))
    }

    fn is_empty(&self) -> bool {
        *self == Listing::default()
    }
}

struct Op {
    kind: u32,
    slot: u32,
    account: u64,
    item: u64,
    price: U256,
    quantity: u64,
    currency: Currency,
}

/// One currency's purchases in the batch: their cost and their fees.
#[derive(Clone, Copy, Default)]
struct Tally {
    currency: Currency,
    volume: U256,
    fees: U256,
}

/// The tallies, in the order of each currency's first purchase.
struct Tallies {
    list: [Tally; MAX_OPS],
    len: usize,
}

impl Tallies {
    /// Where `currency`'s tally is, or goes, and it with a purchase added:
    /// `None` where a total would pass `2^256`. Every tally past the last is
    /// zero, and nothing is recorded but by [`Tallies::set`].
    fn added(&self, currency: Currency, cost: U256, fee: U256) -> Option<(usize, Tally)> {
        let at = self.list[..self.len]
            .iter()
            .position(|t| t.currency == currency)
            .unwrap_or(self.len);
        let t = &self.list[at];
        let tally = Tally {
            currency,
            volume: t.volume.checked_add(cost)?,
            fees: t.fees.checked_add(fee)?,
        };
        Some((at, tally))
    }

    fn set(&mut self, at: usize, tally: Tally) {
        self.list[at] = tally;
        self.len = self.len.max(at + 1);
    }
}

/// A run: consecutive ops on one slot, which one proof opens. No other slot
/// moves while it lasts, so its path holds, and its listing after the opened
/// one is the guest's own arithmetic.
struct Run<'a> {
    slot: u32,
    /// The listing as the proof opened it.
    opened: Listing,
    /// The listing the run's ops have left so far.
    listing: Listing,
    /// The slot's `DEPTH` siblings as advised, read in place. Every proof is
    /// exactly `DEPTH` of them, and that depth, not the leaf's tag, keeps a
    /// listing from opening as a node.
    path: &'a [u8],
}

impl<'a> Run<'a> {
    /// `slot`'s run, opened by the advice's next proof under `table`, or a
    /// panic.
    fn open(slot: u32, advice: &'a [u8], at: &mut usize, table: Digest) -> Run<'a> {
        let listing = Listing::decode(take(advice, at, LISTING));
        let path = take(advice, at, 64 * DEPTH);
        assert!(
            merkle_root(slot, &listing.leaf(), path) == table,
            "marketplace: the advice does not open the table"
        );
        Run {
            slot,
            opened: listing,
            listing,
            path,
        }
    }

    /// The table the run leaves: `table` itself where its listing is as the
    /// proof opened it.
    fn close(&self, table: Digest) -> Digest {
        if self.listing == self.opened {
            table
        } else {
            merkle_root(self.slot, &self.listing.leaf(), self.path)
        }
    }
}

/// What an accepted op leaves in its slot, and a purchase's cost and fee in
/// the listing's currency; a rejection is `None`.
fn settle(listing: Listing, op: &Op, fee_bps: u32) -> Option<(Listing, Option<(U256, U256)>)> {
    let seller = !listing.is_empty() && listing.seller == op.account;
    match op.kind {
        0 if listing.is_empty() && op.account != 0 && op.quantity > 0 && !op.price.is_zero() => {
            let listed = Listing {
                seller: op.account,
                item: op.item,
                price: op.price,
                stock: op.quantity,
                currency: op.currency,
            };
            Some((listed, None))
        }
        1 if seller && !op.price.is_zero() => Some((
            Listing {
                price: op.price,
                currency: op.currency,
                ..listing
            },
            None,
        )),
        2 if !listing.is_empty()
            && op.account != listing.seller
            && (1..=listing.stock).contains(&op.quantity) =>
        {
            let cost = listing.price.checked_mul(U256::from(op.quantity))?;
            let fee = cost.mul_div(U256::from(fee_bps as u64), U256::from(10_000u64))?;
            let left = Listing {
                stock: listing.stock - op.quantity,
                ..listing
            };
            Some((left, Some((cost, fee))))
        }
        3 if seller => Some((Listing::default(), None)),
        _ => None,
    }
}

fn main() {
    let input = guest_sdk::public_input();
    assert!(
        input.len() >= HEADER,
        "marketplace: the public input ended inside the header"
    );
    let before = digest_at(input, 0);
    let fee_bps = u32::from_le_bytes(input[64..68].try_into().expect("four bytes"));
    let n_ops = u32::from_le_bytes(input[68..72].try_into().expect("four bytes")) as usize;
    assert!(fee_bps <= MAX_FEE_BPS, "marketplace: fee_bps is above 1000");
    assert!(
        n_ops <= MAX_OPS && input.len() == HEADER + OP * n_ops,
        "marketplace: the batch is not n_ops records"
    );
    // Asked for only when there is an op: an execution given no advice has no
    // region.
    let advice = if n_ops > 0 { guest_sdk::advice() } else { &[] };

    let mut table = before;
    let (mut applied, mut rejected) = (0u32, 0u32);
    let mut tallies = Tallies {
        list: [Tally::default(); MAX_OPS],
        len: 0,
    };
    let mut at = 0;
    let mut current: Option<Run> = None;
    for k in 0..n_ops {
        let o = &input[HEADER + OP * k..HEADER + OP * (k + 1)];
        let op = Op {
            kind: u32::from_le_bytes(o[..4].try_into().expect("four bytes")),
            slot: u32::from_le_bytes(o[4..8].try_into().expect("four bytes")),
            account: u64_at(o, 8),
            item: u64_at(o, 16),
            price: u256_at(o, 24),
            quantity: u64_at(o, 56),
            currency: o[64..84].try_into().expect("20 bytes"),
        };
        assert!(
            (op.slot as usize) < 1 << DEPTH,
            "marketplace: a slot outside the table"
        );
        if current.as_ref().map(|run| run.slot) != Some(op.slot) {
            if let Some(run) = current.take() {
                table = run.close(table);
            }
            current = Some(Run::open(op.slot, advice, &mut at, table));
        }
        let run = current.as_mut().expect("the op's run is open");
        let listing = run.listing;
        let settled = settle(listing, &op, fee_bps).and_then(|(next, purchase)| match purchase {
            Some((cost, fee)) => Some((next, Some(tallies.added(listing.currency, cost, fee)?))),
            None => Some((next, None)),
        });
        match settled {
            Some((next, tally)) => {
                run.listing = next;
                if let Some((at, t)) = tally {
                    tallies.set(at, t);
                }
                applied += 1;
            }
            None => rejected += 1,
        }
    }
    if let Some(run) = current {
        table = run.close(table);
    }

    let mut out = [0u8; JOURNAL_HEADER + TALLY * MAX_OPS];
    for (i, lane) in before.lanes().iter().chain(table.lanes()).enumerate() {
        out[8 * i..8 * i + 8].copy_from_slice(&lane.to_le_bytes());
    }
    out[128..132].copy_from_slice(&applied.to_le_bytes());
    out[132..136].copy_from_slice(&rejected.to_le_bytes());
    out[136..140].copy_from_slice(&(tallies.len as u32).to_le_bytes());
    for (i, t) in tallies.list[..tallies.len].iter().enumerate() {
        let at = JOURNAL_HEADER + TALLY * i;
        out[at..at + 20].copy_from_slice(&t.currency);
        out[at + 20..at + 52].copy_from_slice(&t.volume.to_le_bytes());
        out[at + 52..at + 84].copy_from_slice(&t.fees.to_le_bytes());
    }
    guest_sdk::commit(&out[..JOURNAL_HEADER + TALLY * tallies.len]);
}

/// The next `n` advised bytes, or a panic: a proof cut short opens nothing.
fn take<'a>(advice: &'a [u8], at: &mut usize, n: usize) -> &'a [u8] {
    let bytes = advice
        .get(*at..*at + n)
        .expect("marketplace: the advice ended inside a run's proof");
    *at += n;
    bytes
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("eight bytes"))
}

fn u256_at(b: &[u8], at: usize) -> U256 {
    U256::from_le_bytes(b[at..at + 32].try_into().expect("32 bytes"))
}

/// The digest at `at`, or a panic: a lane at or above `p` is a second encoding
/// of a node, which no table may be.
fn digest_at(b: &[u8], at: usize) -> Digest {
    Digest::new(core::array::from_fn(|i| u64_at(b, at + 8 * i)))
        .expect("marketplace: a digest's lane is not below p")
}
