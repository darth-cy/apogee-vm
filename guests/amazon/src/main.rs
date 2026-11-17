#![no_std]
#![no_main]
//! A store's users and listings, two tables summarized by one snapshot, and a
//! batch of purchases against them, each a request its buyer signed with
//! Falcon-512.
//!
//! # What this is a fixture for
//!
//! **A database of two tables, one digest.** The convention of the guest
//! manual's §3.3: the users and the listings are each `2^DEPTH` slots, the
//! leaves of a fixed-depth binary tree whose every node is
//! [`poseidon2_compress`] of its children, and the snapshot is
//! `compress(users root, listings root)`, the schema's order. Anyone buys and
//! anyone sells: a user is one record whichever it does. The public input
//! carries the snapshot before the batch and the batch; the journal, the
//! snapshot after it.
//!
//! **Each record opened once.** The advice holds every record the batch reads,
//! each once, in ascending slot order per table, and the batch runs against
//! that working set in memory, finding a record by binary search: a purchase
//! moves the buyer's and the seller's balances and the listing's stock there,
//! however many purchases touch them, so a seller may spend later in the batch
//! what it earned earlier in it. After the batch each record is checked and
//! written back once, along a Merkle path the advice holds under its table's
//! root as it then stands: one [`merkle_root`] call opens the record as the
//! advice gave it, the guest panicking where the roots differ, and a second
//! writes the record the batch left, where it differs. Nothing advised is
//! trusted, and nothing is committed before every record read is opened.
//!
//! **Signed requests.** A request is 64 bytes, exactly the message its buyer
//! signs with Falcon-512 under the key whose digest the buyer's record holds,
//! the buyer's nonce and the store's market id inside it, so a request spends
//! its nonce at most once, and in one store. A key is advised beside its
//! user's record and read when its user first signs: decoded, its digest
//! checked against the record's, and kept for the user's later requests. Its
//! bytes are absorbed once, into the sponge its digest and every HashToPoint
//! of its user's signatures continue from. [`PublicKey::verify`] is the SDK's:
//! its lattice check is the Falcon-512 precompile, and HashToPoint's
//! permutations Poseidon2's.
//!
//! **The order is the sequencer's.** The guest settles the requests in the
//! order the batch gives and never sorts. A buyer's nonces order its own
//! requests; the rest is the sequencer's policy, each listing's requests
//! gathered, say, and it becomes part of the batch: which buyer a listing's
//! last unit goes to, and whether a seller has been paid when it buys, follow
//! the order. The order costs nothing here, as each record is opened once
//! however the batch interleaves them.
//!
//! # The tables
//!
//! ```text
//! user       0..64   key       8 lanes, u64 LE, each below p: the digest of the user's
//!                              Falcon-512 public key; zero in a slot with no account
//!           64..96   balance   U256 LE
//!           96..104  nonce     u64: the user's next request's
//! listing    0..4    seller    u32: a user's slot
//!            4..12   item      u64
//!           12..44   price     U256 LE: a unit's
//!           44..52   stock     u64: the units left
//! ```
//!
//! A user's leaf is one permutation: the key, then the balance and the nonce,
//! 40 bytes packed seven to a lane into six lanes below `2^56 < p`, a zero and
//! the tag 1: `compress(key, [lanes 0..6, 0, 1])`. A listing's is its 52 bytes
//! packed into eight lanes, seven zeros and the tag 2: `compress(lanes 0..8,
//! [0, 0, 0, 0, 0, 0, 0, 2])`. Each packing is injective, every lane is below
//! `p` (a key's, by [`Digest::new`]), and a tag names its table's encoding. A
//! user is an account where its key is not zero, and only an account signs or
//! is paid. An empty slot holds the all-zero record: a user with no account, a
//! listing with no stock.
//!
//! A key's digest is its KeyDigest (`docs/spec/precompiles.md` §8.7): the
//! first eight lanes HashToPoint's sponge squeezes after the context, the
//! key's bytes and an empty field tagged 5. It is defined for any bytes: an
//! advised key that does not decode is checked against its record all the
//! same, and its user's requests are rejected.
//!
//! The tags do not keep a leaf's preimage apart from a node's: a node
//! compresses any two digests, and a leaf's sixteen lanes are two digests as
//! well. The depth does. Every path is `DEPTH` siblings, so a record's leaf is
//! always `DEPTH` compressions below its table's root, where the table's leaves
//! are and none of its nodes. A tree whose paths varied in length would need
//! its leaves hashed apart from its nodes.
//!
//! # The public input
//!
//! ```text
//! header     0..64   snapshot  8 lanes, u64 LE, each below p: the tables before the batch
//!           64..72   market    u64: this store's id
//!           72..76   n         u32, at most MAX_REQUESTS
//! request    0..4    buyer     u32: a user's slot, below 2^DEPTH
//!            4..8    listing   u32: a listing's slot, below 2^DEPTH
//!            8..16   quantity  u64
//!           16..48   max price U256 LE: the most the buyer pays a unit
//!           48..56   nonce     u64: the buyer's
//!           56..64   market    u64: the store the buyer signed for
//! ```
//!
//! The input is the header and its `n` requests and nothing more, so no byte of
//! the statement goes unread.
//!
//! # The advice
//!
//! ```text
//! roots           0..128  the users root, then the listings root: 8 lanes each, u64 LE,
//!                         each below p
//! users           u32 count, then for each user the batch reads, in ascending slot order:
//!                         its slot u32, its record, and for an account its public key,
//!                         897 bytes
//! listings        u32 count, then for each listing the batch reads, in ascending slot
//!                         order: its slot u32, its record
//! signatures      666 bytes a request, in the batch's order
//!                 zeros to the next multiple of four bytes
//! paths           for each user above in its order, then each listing: DEPTH siblings from
//!                 the leaf up, 64 bytes each, under its table's root as the records
//!                 before it left it
//! ```
//!
//! The records are the snapshot's, before the batch; the advice may hold more
//! than the batch reads, each opened all the same. A key is read when its user
//! first signs a request the guest gets as far as checking, and a signature
//! when its request is. A path is read in place by the precompile, a word at a
//! time, each sibling's lanes mod `p`: a sibling's encoding is the prover's,
//! and no root depends on it.
//!
//! # The batch
//!
//! Each request in turn, against the records as the requests before it left
//! them. It is **rejected**, and changes nothing, where its market is not the
//! header's, its buyer has no account, its nonce is not the buyer's or is
//! `2^64 − 1`, which leaves none after it, or its signature does not verify
//! under the buyer's key. Otherwise the nonce is spent, and the purchase is
//! **applied** where the listing holds the quantity, at least one unit, at a
//! price no more than the max price, for a seller who is not the buyer and has
//! an account, a slot of the users table with a key, at a cost, `price ·
//! quantity`, below `2^256` and no more than the buyer's balance, that takes
//! neither the seller's balance nor the batch's volume to `2^256`: the cost
//! moves from the buyer's balance to the seller's, the quantity leaves the
//! stock, and the cost joins the volume. Otherwise it is **declined**.
//!
//! A record is read where a check first needs it: the buyer's once the market
//! matches, the listing's once the nonce is spent, and the seller's once the
//! listing's terms and the buyer's balance allow the purchase. A record the
//! batch reads and the advice does not hold is a panic.
//!
//! # The journal
//!
//! ```text
//!            0..64   the snapshot before the batch
//!           64..128  the snapshot after it
//!          128..132  applied   u32
//!          132..136  declined  u32
//!          136..140  rejected  u32
//!          140..172  volume    U256 LE: the applied purchases' cost
//! ```
//!
//! A malformed batch, a digest in the input or the advice with a lane at or
//! above `p`, an advised key that is not its user's, and a record or a path
//! that does not open its table, panic.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

use constants::guest_memory;
use guest_sdk::falcon512::{self, PublicKey, PUBLIC_KEY_BYTES, SIGNATURE_BYTES};
use guest_sdk::{merkle_root, poseidon2_compress, Digest, U256};

guest_sdk::entry!(main);

/// Each tree's depth: `2^20` slots.
const DEPTH: usize = 20;
const PATH: usize = 64 * DEPTH;
const USER: usize = 104;
const LISTING: usize = 52;
const HEADER: usize = 76;
const REQUEST: usize = 64;
const JOURNAL: usize = 172;
const PAYLOAD: usize = guest_memory::PUBLIC_PAYLOAD_BYTES as usize;
/// As many requests as fit the public input beside its header.
const MAX_REQUESTS: usize = (PAYLOAD - HEADER) / REQUEST;
/// The tag lanes naming a user's encoding and a listing's.
const USER_TAG: u64 = 1;
const LISTING_TAG: u64 = 2;

// A user's balance and nonce pack into six lanes, a listing into eight.
const _: () = assert!((USER - 64).div_ceil(7) == 6 && LISTING.div_ceil(7) == 8);

#[derive(Clone, Copy, PartialEq, Eq)]
struct User {
    key: Digest,
    balance: U256,
    nonce: u64,
}

impl User {
    fn decode(b: &[u8]) -> User {
        User {
            key: digest_at(b, 0),
            balance: u256_at(b, 64),
            nonce: u64_at(b, 96),
        }
    }

    /// Whether the slot holds an account: a key to sign with and to be paid
    /// under.
    fn is_account(&self) -> bool {
        self.key != Digest::default()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Listing {
    seller: u32,
    item: u64,
    price: U256,
    stock: u64,
}

impl Listing {
    fn decode(b: &[u8]) -> Listing {
        Listing {
            seller: u32_at(b, 0),
            item: u64_at(b, 4),
            price: u256_at(b, 12),
            stock: u64_at(b, 44),
        }
    }
}

/// A record whose leaf a tree holds.
trait Record: Copy + PartialEq {
    fn leaf(&self) -> Digest;
}

impl Record for User {
    fn leaf(&self) -> Digest {
        let mut bytes = [0u8; USER - 64];
        bytes[..32].copy_from_slice(&self.balance.to_le_bytes());
        bytes[32..].copy_from_slice(&self.nonce.to_le_bytes());
        let mut lanes = [0u64; 8];
        pack(&bytes, &mut lanes);
        lanes[7] = USER_TAG;
        poseidon2_compress(&self.key, &digest(&lanes))
    }
}

impl Record for Listing {
    fn leaf(&self) -> Digest {
        let mut bytes = [0u8; LISTING];
        bytes[..4].copy_from_slice(&self.seller.to_le_bytes());
        bytes[4..12].copy_from_slice(&self.item.to_le_bytes());
        bytes[12..44].copy_from_slice(&self.price.to_le_bytes());
        bytes[44..].copy_from_slice(&self.stock.to_le_bytes());
        let mut lanes = [0u64; 16];
        pack(&bytes, &mut lanes);
        lanes[15] = LISTING_TAG;
        poseidon2_compress(&digest(&lanes[..8]), &digest(&lanes[8..]))
    }
}

/// A record the batch reads: as the advice opened it, and as the batch leaves
/// it.
struct Held<R> {
    slot: u32,
    opened: R,
    now: R,
}

/// A user's public key, as far as the batch has read it.
enum Key<'a> {
    /// No account, so no key advised.
    Absent,
    /// The advised bytes, unread: the user has not yet signed.
    Advised(&'a [u8]),
    /// The key the bytes decode to, checked against the user's record.
    Decoded(Box<PublicKey>),
    /// The user's key bytes, which decode to no key: nothing verifies.
    Malformed,
}

struct Request {
    buyer: u32,
    listing: u32,
    quantity: u64,
    max_price: U256,
    nonce: u64,
    market: u64,
}

impl Request {
    fn decode(b: &[u8]) -> Request {
        Request {
            buyer: u32_at(b, 0),
            listing: u32_at(b, 4),
            quantity: u64_at(b, 8),
            max_price: u256_at(b, 16),
            nonce: u64_at(b, 48),
            market: u64_at(b, 56),
        }
    }
}

/// A request's outcome, its counter's place in the journal.
#[derive(Clone, Copy)]
enum Outcome {
    Applied,
    Declined,
    Rejected,
}

/// The working set: every record the advice holds, as opened and as the
/// requests so far leave it, each user's key, and the volume so far.
struct Store<'a> {
    users: Vec<Held<User>>,
    keys: Vec<Key<'a>>,
    listings: Vec<Held<Listing>>,
    volume: U256,
}

impl<'a> Store<'a> {
    /// The advised users and listings from `at`, or a panic.
    fn read(advice: &'a [u8], at: &mut usize) -> Store<'a> {
        let count = u32_at(take(advice, at, 4), 0) as usize;
        let mut users: Vec<Held<User>> = Vec::with_capacity(count);
        let mut keys = Vec::with_capacity(count);
        for _ in 0..count {
            let slot = next_slot(users.last().map(|h| h.slot), take(advice, at, 4));
            let user = User::decode(take(advice, at, USER));
            keys.push(if user.is_account() {
                Key::Advised(take(advice, at, PUBLIC_KEY_BYTES))
            } else {
                Key::Absent
            });
            users.push(Held {
                slot,
                opened: user,
                now: user,
            });
        }
        let count = u32_at(take(advice, at, 4), 0) as usize;
        let mut listings: Vec<Held<Listing>> = Vec::with_capacity(count);
        for _ in 0..count {
            let slot = next_slot(listings.last().map(|h| h.slot), take(advice, at, 4));
            let listing = Listing::decode(take(advice, at, LISTING));
            listings.push(Held {
                slot,
                opened: listing,
                now: listing,
            });
        }
        Store {
            users,
            keys,
            listings,
            volume: U256::ZERO,
        }
    }

    /// The request `message` signed by `signature`, settled against the
    /// working set: the records it changes changed there.
    fn settle(&mut self, message: &[u8], signature: &[u8], market: u64) -> Outcome {
        let r = Request::decode(message);
        assert!(
            (r.buyer as usize) < 1 << DEPTH && (r.listing as usize) < 1 << DEPTH,
            "amazon: a slot outside its table"
        );
        if r.market != market {
            return Outcome::Rejected;
        }
        let b = find(&self.users, r.buyer);
        let buyer = self.users[b].now;
        let next = match r.nonce.checked_add(1) {
            Some(next) if buyer.is_account() && r.nonce == buyer.nonce => next,
            _ => return Outcome::Rejected,
        };
        if !verifies(&mut self.keys[b], &buyer.key, message, signature) {
            return Outcome::Rejected;
        }
        self.users[b].now.nonce = next;

        let l = find(&self.listings, r.listing);
        let listing = self.listings[l].now;
        let cost = match listing.price.checked_mul(U256::from(r.quantity)) {
            Some(cost)
                if (1..=listing.stock).contains(&r.quantity)
                    && listing.price <= r.max_price
                    && listing.seller != r.buyer
                    && (listing.seller as usize) < 1 << DEPTH
                    && cost <= buyer.balance =>
            {
                cost
            }
            _ => return Outcome::Declined,
        };
        let s = find(&self.users, listing.seller);
        let seller = self.users[s].now;
        let (Some(paid), Some(volume)) = (
            seller.balance.checked_add(cost),
            self.volume.checked_add(cost),
        ) else {
            return Outcome::Declined;
        };
        if !seller.is_account() {
            return Outcome::Declined;
        }
        self.users[b].now.balance = buyer.balance - cost;
        self.users[s].now.balance = paid;
        self.listings[l].now.stock = listing.stock - r.quantity;
        self.volume = volume;
        Outcome::Applied
    }
}

/// Whether `signature` signs `message` under the key of the user whose record
/// holds `digest`: the advised bytes decoded and their digest checked against
/// `digest` the first time, from the decoded key where they decode, and the key
/// they decoded to each time.
fn verifies(key: &mut Key, digest: &Digest, message: &[u8], signature: &[u8]) -> bool {
    if let Key::Advised(bytes) = *key {
        let decoded = PublicKey::decode(bytes);
        let advised = match &decoded {
            Some(key) => key.digest(),
            None => falcon512::key_digest(bytes),
        };
        assert!(
            advised == *digest,
            "amazon: an advised key is not its user's"
        );
        *key = decoded.map_or(Key::Malformed, |k| Key::Decoded(Box::new(k)));
    }
    match key {
        Key::Decoded(key) => key.verify(message, signature),
        _ => false,
    }
}

/// Where `slot`'s record is in `held`, or a panic: the batch reads a record
/// the advice does not hold.
fn find<R>(held: &[Held<R>], slot: u32) -> usize {
    held.binary_search_by_key(&slot, |h| h.slot)
        .expect("amazon: the advice does not hold a record the batch reads")
}

/// `held`'s records written back to the tree `root`, each opened by the
/// advice's next path under the root as the records before it left it, and
/// written along it where the batch changed it: the tree the batch leaves, or
/// a panic.
fn write_back<R: Record>(
    held: &[Held<R>],
    mut root: Digest,
    advice: &[u8],
    at: &mut usize,
) -> Digest {
    for h in held {
        let path = take(advice, at, PATH);
        assert!(
            merkle_root(h.slot, &h.opened.leaf(), path) == root,
            "amazon: the advice does not open the table"
        );
        if h.now != h.opened {
            root = merkle_root(h.slot, &h.now.leaf(), path);
        }
    }
    root
}

fn main() {
    let input = guest_sdk::public_input();
    assert!(
        input.len() >= HEADER,
        "amazon: the public input ended inside the header"
    );
    let before = digest_at(input, 0);
    let market = u64_at(input, 64);
    let n = u32_at(input, 72) as usize;
    assert!(
        n <= MAX_REQUESTS && input.len() == HEADER + REQUEST * n,
        "amazon: the batch is not n requests"
    );

    let mut counts = [0u32; 3];
    let (mut after, mut volume) = (before, U256::ZERO);
    // Asked for only when there is a request: an execution given no advice
    // has no region.
    if n > 0 {
        let advice = guest_sdk::advice();
        let mut at = 0;
        let users_root = digest_at(take(advice, &mut at, 64), 0);
        let listings_root = digest_at(take(advice, &mut at, 64), 0);
        assert!(
            poseidon2_compress(&users_root, &listings_root) == before,
            "amazon: the advised roots are not the snapshot"
        );
        let mut store = Store::read(advice, &mut at);
        let signatures = take(advice, &mut at, SIGNATURE_BYTES * n);
        let requests = input[HEADER..].chunks_exact(REQUEST);
        for (request, signature) in requests.zip(signatures.chunks_exact(SIGNATURE_BYTES)) {
            counts[store.settle(request, signature, market) as usize] += 1;
        }
        // The paths start on a word: the precompile reads them in place.
        at = at.next_multiple_of(4);
        let users = write_back(&store.users, users_root, advice, &mut at);
        let listings = write_back(&store.listings, listings_root, advice, &mut at);
        after = poseidon2_compress(&users, &listings);
        volume = store.volume;
    }

    let mut out = [0u8; JOURNAL];
    for (i, lane) in before.lanes().iter().chain(after.lanes()).enumerate() {
        out[8 * i..8 * i + 8].copy_from_slice(&lane.to_le_bytes());
    }
    for (i, count) in counts.iter().enumerate() {
        out[128 + 4 * i..132 + 4 * i].copy_from_slice(&count.to_le_bytes());
    }
    out[140..].copy_from_slice(&volume.to_le_bytes());
    guest_sdk::commit(&out);
}

/// The slot `bytes` hold, if it is in its table and above `last`, the slot
/// advised before it there, or a panic: a record advised twice could be read
/// as two.
fn next_slot(last: Option<u32>, bytes: &[u8]) -> u32 {
    let slot = u32_at(bytes, 0);
    assert!(
        (slot as usize) < 1 << DEPTH && last.is_none_or(|last| last < slot),
        "amazon: the advised slots do not ascend within their table"
    );
    slot
}

/// The next `n` advised bytes, or a panic.
fn take<'a>(advice: &'a [u8], at: &mut usize, n: usize) -> &'a [u8] {
    let bytes = advice
        .get(*at..*at + n)
        .expect("amazon: the advice ended early");
    *at += n;
    bytes
}

/// `bytes` packed seven to a lane, little-endian, into `lanes`, each lane
/// below `2^56 < p`; the lanes past the bytes are left as they are. Seven
/// whole bytes a pass, a copy of fixed length: half the cycles of a byte a
/// pass.
fn pack(bytes: &[u8], lanes: &mut [u64]) {
    let (sevens, rest) = bytes.as_chunks::<7>();
    for (lane, seven) in lanes.iter_mut().zip(sevens) {
        let mut b = [0u8; 8];
        b[..7].copy_from_slice(seven);
        *lane = u64::from_le_bytes(b);
    }
    if !rest.is_empty() {
        let mut b = [0u8; 8];
        b[..rest.len()].copy_from_slice(rest);
        lanes[sevens.len()] = u64::from_le_bytes(b);
    }
}

/// Eight lanes the guest packed, each below `p`, as a digest.
fn digest(lanes: &[u64]) -> Digest {
    Digest::new(lanes.try_into().expect("eight lanes")).expect("seven bytes are below p")
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("four bytes"))
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
        .expect("amazon: a digest's lane is not below p")
}
