#![no_std]
#![no_main]
//! A marketplace's listings table, summarized by its Merkle root, and a batch of
//! operations against it: list an item, reprice it, buy from it, delist it.
//!
//! # What this is a fixture for
//!
//! **A database a proof follows by its root.** The table is `2^DEPTH` listing
//! slots, the leaves of a fixed-depth binary tree whose every node is
//! [`poseidon2_compress`], the Poseidon2 precompile. The public input carries the
//! root before the batch and the batch; the advice carries, for each operation,
//! the slot's listing and its `DEPTH` siblings, a Merkle proof. Nothing advised
//! is trusted: the guest rebuilds the root from the proof before it reads the
//! listing, panics where the two differ, and builds the next root from the
//! listing it writes, along the same path. A verifier holding the roots follows
//! the whole table, `2 · DEPTH + 2` permutations an operation, without anyone
//! publishing it.
//!
//! Prices and the totals are [`U256`], an ERC-20 amount's width: a purchase costs
//! `price · quantity` and pays `cost · fee_bps / 10_000` in fees, the
//! `MUL_DIV_U256` precompile.
//!
//! # The leaf
//!
//! A listing is 56 bytes, packed seven to a lane, below `2^56 < p`, so the
//! packing is injective. Its leaf is `compress(lanes, [LEAF, 0, …])`, the tag
//! keeping a leaf's preimage from an internal node's. An empty slot holds the
//! all-zero listing.
//!
//! ```text
//! listing    0..8    seller    u64; 0 only in an empty slot
//!            8..16   item      u64
//!           16..48   price     U256 LE
//!           48..56   stock     u64
//! ```
//!
//! # The public input
//!
//! ```text
//! header     0..64   root      8 lanes, u64 LE: the table before the batch
//!           64..68   fee_bps   u32, at most 1000
//!           68..72   n_ops     u32, at most MAX_OPS
//! op         0..4    kind      u32: 0 list, 1 reprice, 2 buy, 3 delist
//!            4..8    slot      u32, below 2^DEPTH
//!            8..16   account   u64: the seller; a buy's buyer
//!           16..24   item      u64: a list's
//!           24..56   price     U256 LE: a list's or a reprice's
//!           56..64   quantity  u64: a list's stock, a buy's count
//! ```
//!
//! # The advice
//!
//! For each op, in order: the slot's listing, then its `DEPTH` siblings from the
//! leaf up, 64 bytes each, under the root the ops before it left.
//!
//! # The journal
//!
//! ```text
//!            0..64   the root before the batch
//!           64..128  the root after it
//!          128..132  applied   u32
//!          132..136  rejected  u32
//!          136..168  volume    U256: every purchase's cost
//!          168..200  fees      U256: every purchase's fee
//! ```
//!
//! An op that breaks a rule — a slot already listed, an account not the
//! listing's seller, a purchase past the stock or by the seller — is rejected
//! and counted, and leaves the table as it was. A malformed batch, and a proof
//! that does not open the root, panic.

use constants::guest_memory;
use guest_sdk::{poseidon2_compress, U256};

guest_sdk::entry!(main);

/// The tree's depth: `2^20` slots.
const DEPTH: usize = 20;
const LISTING: usize = 56;
const HEADER: usize = 72;
const OP: usize = 64;
/// As many ops as fit the public input window beside the header.
const MAX_OPS: usize = (guest_memory::PUBLIC_PAYLOAD_BYTES as usize - HEADER) / OP;
const MAX_FEE_BPS: u32 = 1_000;
/// The tag lane of a leaf's preimage.
const LEAF: u64 = 1;

type Digest = [u64; 8];

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Listing {
    seller: u64,
    item: u64,
    price: U256,
    stock: u64,
}

impl Listing {
    fn decode(b: &[u8]) -> Listing {
        Listing {
            seller: u64_at(b, 0),
            item: u64_at(b, 8),
            price: u256_at(b, 16),
            stock: u64_at(b, 48),
        }
    }

    fn leaf(&self) -> Digest {
        let mut bytes = [0u8; LISTING];
        bytes[..8].copy_from_slice(&self.seller.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.item.to_le_bytes());
        bytes[16..48].copy_from_slice(&self.price.to_le_bytes());
        bytes[48..].copy_from_slice(&self.stock.to_le_bytes());
        let lanes: Digest = core::array::from_fn(|i| {
            let mut lane = [0u8; 8];
            lane[..7].copy_from_slice(&bytes[7 * i..7 * i + 7]);
            u64::from_le_bytes(lane)
        });
        let mut tag = [0u64; 8];
        tag[0] = LEAF;
        poseidon2_compress(&lanes, &tag)
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
}

/// The root `path` opens with `leaf` at `slot`: slot bit `i` says which side
/// of level `i` the node is.
fn root(slot: u32, leaf: Digest, path: &[Digest; DEPTH]) -> Digest {
    let mut node = leaf;
    for (level, sibling) in path.iter().enumerate() {
        node = match slot >> level & 1 {
            0 => poseidon2_compress(&node, sibling),
            _ => poseidon2_compress(sibling, &node),
        };
    }
    node
}

/// What an accepted op leaves in its slot, and a purchase's cost and fee; a
/// rejection is `None`.
fn settle(listing: Listing, op: &Op, fee_bps: u32) -> Option<(Listing, U256, U256)> {
    let zero = U256::ZERO;
    let seller = !listing.is_empty() && listing.seller == op.account;
    match op.kind {
        0 if listing.is_empty() && op.account != 0 && op.quantity > 0 && !op.price.is_zero() => {
            let listed = Listing {
                seller: op.account,
                item: op.item,
                price: op.price,
                stock: op.quantity,
            };
            Some((listed, zero, zero))
        }
        1 if seller && !op.price.is_zero() => Some((
            Listing {
                price: op.price,
                ..listing
            },
            zero,
            zero,
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
            Some((left, cost, fee))
        }
        3 if seller => Some((Listing::default(), zero, zero)),
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
        n_ops <= MAX_OPS && input.len() >= HEADER + OP * n_ops,
        "marketplace: the batch is not n_ops records"
    );
    // Asked for only when there is an op: a run given no advice has no region.
    let advice = if n_ops > 0 { guest_sdk::advice() } else { &[] };

    let mut table = before;
    let (mut applied, mut rejected) = (0u32, 0u32);
    let (mut volume, mut fees) = (U256::ZERO, U256::ZERO);
    let mut at = 0;
    for k in 0..n_ops {
        let o = &input[HEADER + OP * k..HEADER + OP * (k + 1)];
        let op = Op {
            kind: u32::from_le_bytes(o[..4].try_into().expect("four bytes")),
            slot: u32::from_le_bytes(o[4..8].try_into().expect("four bytes")),
            account: u64_at(o, 8),
            item: u64_at(o, 16),
            price: u256_at(o, 24),
            quantity: u64_at(o, 56),
        };
        assert!(
            (op.slot as usize) < 1 << DEPTH,
            "marketplace: a slot outside the table"
        );
        let listing = Listing::decode(take(advice, &mut at, LISTING));
        let mut path = [[0u64; 8]; DEPTH];
        for sibling in path.iter_mut() {
            *sibling = digest_at(take(advice, &mut at, 64), 0);
        }
        assert!(
            root(op.slot, listing.leaf(), &path) == table,
            "marketplace: the advice does not open the table"
        );
        let settled = settle(listing, &op, fee_bps).and_then(|(next, cost, fee)| {
            Some((next, volume.checked_add(cost)?, fees.checked_add(fee)?))
        });
        match settled {
            Some((next, v, f)) => {
                table = root(op.slot, next.leaf(), &path);
                (volume, fees) = (v, f);
                applied += 1;
            }
            None => rejected += 1,
        }
    }

    let mut out = [0u8; 200];
    for (i, lane) in before.iter().chain(&table).enumerate() {
        out[8 * i..8 * i + 8].copy_from_slice(&lane.to_le_bytes());
    }
    out[128..132].copy_from_slice(&applied.to_le_bytes());
    out[132..136].copy_from_slice(&rejected.to_le_bytes());
    out[136..168].copy_from_slice(&volume.to_le_bytes());
    out[168..].copy_from_slice(&fees.to_le_bytes());
    guest_sdk::commit(&out);
}

/// The next `n` advised bytes, or a panic: a proof cut short opens nothing.
fn take<'a>(advice: &'a [u8], at: &mut usize, n: usize) -> &'a [u8] {
    let bytes = advice
        .get(*at..*at + n)
        .expect("marketplace: the advice ended inside an op's proof");
    *at += n;
    bytes
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("eight bytes"))
}

fn u256_at(b: &[u8], at: usize) -> U256 {
    U256::from_le_bytes(b[at..at + 32].try_into().expect("32 bytes"))
}

fn digest_at(b: &[u8], at: usize) -> Digest {
    core::array::from_fn(|i| u64_at(b, at + 8 * i))
}
