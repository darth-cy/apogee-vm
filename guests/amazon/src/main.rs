#![no_std]
#![no_main]
//! A store's users and listings, two tables summarized by one snapshot, and a
//! batch of purchases against them, each a request its buyer signed with
//! Falcon-512.
//!
//! # What this is a fixture for
//!
//! **A database of two tables, one digest.** The convention of the guest
//! manual's §3.3: each table is a crit-bit trie over its keys, the users keyed
//! by address and the listings by id, and the snapshot is
//! [`poseidon2_compress`] of the users root and the listings root, the
//! schema's order. Anyone buys and anyone sells: a user is one record whichever
//! it does. The public input carries the snapshot before the batch; the
//! journal, the snapshot after it.
//!
//! **Each record opened once.** The advice holds every record the batch reads
//! and no other, each once, the users in ascending address order and the
//! listings in ascending id order, and each table's batched proof of their
//! keys. [`Trie::open`] reads a table's pruned trie from its records' leaves
//! and its proof, and the two roots, [`Trie::root`] each, compressed, must be
//! the snapshot. The batch runs against that working set in memory, finding a
//! record by binary search: a purchase moves the buyer's and the seller's
//! balances and the listing's stock there, however many purchases touch them,
//! so a seller may spend later in the batch what it earned earlier in it. After
//! the batch each record it changed is set in its trie, once, and the two roots
//! give the snapshot after. Nothing advised is trusted: every record is held to
//! the snapshot before the batch reads it.
//!
//! **Users by address.** A user is named by its address, 256 bits: the first
//! 32 bytes of K, the key digest of its Falcon-512 public key
//! (`docs/spec/precompiles.md` §7.7), and its address is its key in the users
//! table. A request names its buyer by address, and a listing its seller.
//!
//! **Signed requests.** A request is 92 bytes, exactly the message its buyer
//! signs with Falcon-512 under the context `apogee/amazon/purchase/v1`, the
//! buyer's address, its nonce and the store's market id inside it, so a
//! request spends its nonce at most once, and in one store. A user's key is
//! advised where the user first signs, ahead of that request's signature, and
//! read there: decoded, K computed from it, and K's address checked against
//! the buyer's, by which the request found the record; then kept for the
//! user's later requests, each verified under that K. A key that does not
//! decode, or is not its buyer's, ends the execution, as does a signature that
//! does not verify: [`PublicKey::decode`] and [`PublicKey::verify`] are the
//! SDK's, which panic, or whose decode call refuses an encoding, rather than
//! answer a verdict. Their decoding and lattice check are the Falcon-512
//! precompiles, and K's and HashToPoint's permutations Poseidon2's.
//!
//! **The requests are advice.** The statement is that signed requests, each
//! its buyer's at that buyer's nonce, take the snapshot to the next. The
//! requests and their signatures are advice the prover chooses, so the proof
//! does not say which requests a batch settled, only that each one was signed
//! and valid for this store and snapshot: no one but its buyer can sign a
//! request. Every request in a batch applies. One that cannot, or whose
//! signature does not verify under its buyer's key, is a malformed batch, a
//! panic, never an outcome. The sequencer checks the requests and their
//! signatures and drops each one that cannot apply before it batches them, as
//! a rollup's block producer does.
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
//! user      key     0..32   address   K's first 32 bytes, K the key digest of the
//!                                     user's Falcon-512 public key
//!           value   0..32   balance   U256 LE
//!                  32..40   nonce     u64: the user's next request's
//! listing   key     0..4    id        u32 big-endian
//!           value   0..32   seller    an address
//!                  32..40   item      u64
//!                  40..72   price     U256 LE: a unit's
//!                  72..80   stock     u64: the units left
//! ```
//!
//! A record's leaf is [`mpt::leaf`] of its key and its value, one permutation
//! of the two packed seven bytes to a lane, fed forward, and a table's root is
//! its trie's, the trie precompile's hash of it (`docs/spec/precompiles.md`'s
//! MPT section). A leaf binds neither length, and each table's keys are one
//! length and its values one width, 40 bytes a user's and 80 a listing's. A
//! listing's key is its id big-endian, so the trie's order, its keys' byte
//! order, is the ids'.
//!
//! The batch sets leaves and neither inserts nor removes a key: a request
//! whose buyer, listing or seller the advice does not hold is a malformed
//! batch, a panic, whether or not its table holds it.
//!
//! # The public input
//!
//! ```text
//!            0..64   snapshot  8 lanes, u64 LE, each below p: the tables before the batch
//!           64..72   market    u64: this store's id
//! ```
//!
//! The input is these 72 bytes and nothing more: any other length is a panic.
//!
//! # The advice
//!
//! ```text
//! users           u32 count, then for each user the batch reads, in ascending address
//!                         order: its address and its value, 72 bytes
//! listings        u32 count, then for each listing the batch reads, in ascending id
//!                         order: its id u32, then its value, 84 bytes
//! users proof     the users table's batched proof of the users above
//! listings proof  the listings table's, of the listings above
//! batch           u32 n, then for each request, in the batch's order: the request; at
//!                         its buyer's first, the buyer's public key, h's 896 bytes;
//!                         then the request's signature, its 40-byte salt and s2
//!                         compressed through the word holding its last bit
//!
//! request    0..32   buyer     an address
//!           32..36   listing   u32: a listing's id
//!           36..44   quantity  u64
//!           44..76   max price U256 LE: the most the buyer pays a unit
//!           76..84   nonce     u64: the buyer's
//!           84..92   market    u64: the store the buyer signed for
//! ```
//!
//! The advice is these entries and nothing more: a byte after the last
//! signature is a panic.
//!
//! Every entry is a whole number of words, so each record, each proof, each
//! request, each key, each signature and its compressed `s2`, 40 bytes in,
//! start on a word: the trie precompile reads a proof's digests in place, the
//! decode call and the Falcon-512 precompile read keys and signatures in place,
//! a word at a time, and K and HashToPoint absorb them a word at a time. A key
//! and a signature are the SDK's advised forms, v1.2's encodings without their
//! headers and the signature's padding: a key is 896 bytes, and a signature
//! `40 + 4·⌈end/32⌉`, `end` the bit after its last coefficient, which the
//! decode call finds, the bits after it in its last word zeros, which the call
//! checks. The cursor moves past a signature by the length
//! [`PublicKey::verify`] returns. No byte of the advice is padding.
//!
//! A table's keys ascend strictly, which [`Trie::open`] checks, so no record is
//! advised twice. A proof is the siblings' depths and owners, then their
//! digests, each read by the precompile lane by lane mod `p`: a sibling's
//! encoding is the prover's, and no root depends on it. The records are the
//! snapshot's, before the batch, and one the batch does not read is a panic.
//! The batch is read a request at a time, so it holds a key for each user that
//! buys, at its first request, and a signature for each request: a key or a
//! signature missing, or one more, shifts every read after it, which a
//! request's checks, a key's decoding or address, a signature's decoding or
//! verification, or the advice's end refuses.
//!
//! # The batch
//!
//! Each request in turn, against the records as the requests before it left
//! them. Its market is the public input's, and its nonce is the buyer's and
//! not `2^64 − 1`, which leaves none after it; its signature, after its
//! buyer's key at the buyer's first request, verifies under the buyer's key
//! and the context; and the listing holds the quantity, at least one unit, at
//! a price no more than the max price, for a seller who is not the buyer, at a
//! cost, `price · quantity`, below `2^256` and no more than the buyer's
//! balance, that takes neither the seller's balance nor the batch's volume to
//! `2^256`. Otherwise the batch is malformed and the execution ends. The
//! request is **applied**: the buyer's nonce is spent, the cost moves from the
//! buyer's balance to the seller's, the quantity leaves the stock, and the
//! cost joins the volume.
//!
//! A record is read where a check first needs it: the buyer's once the market
//! matches, the listing's once the nonce is spent, and the seller's once the
//! listing's terms and the buyer's balance allow the purchase. A record the
//! batch reads and the advice does not hold is a panic, and so, where the
//! records are written back, is one the advice holds and the batch does not
//! read.
//!
//! # The journal
//!
//! ```text
//!            0..64   the snapshot before the batch
//!           64..128  the snapshot after it
//!          128..132  purchases u32: n, as every request applies
//!          132..164  volume    U256 LE: the purchases' cost
//! ```
//!
//! A public input that is not 72 bytes, a request that is not valid, advice
//! that is not exactly what the batch reads, a key that does not decode or is
//! not its buyer's, a signature that does not decode or verify, a snapshot
//! with a lane at or above `p`, and records or a proof that do not open the
//! snapshot, end the execution: a panic, or for a key or a signature that is
//! not one, the decode call's refusal.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

use guest_sdk::falcon512::{PublicKey, KEY_BYTES};
use guest_sdk::mpt::{self, Trie};
use guest_sdk::{poseidon2_compress, Digest, U256};

guest_sdk::entry!(main);

/// A user's record: its address, its key, then its value.
const USER: usize = 72;
/// A listing's value; its record is its id, then its value.
const LISTING: usize = 80;
const INPUT: usize = 72;
const REQUEST: usize = 92;
const JOURNAL: usize = 164;

// Every advised entry is a whole number of words, a proof's by its form and a
// signature's by the SDK's, so each record, each proof and each request starts
// on a word, as do each key and each signature.
const _: () = assert!(
    USER.is_multiple_of(4)
        && (4 + LISTING).is_multiple_of(4)
        && KEY_BYTES.is_multiple_of(4)
        && REQUEST.is_multiple_of(4)
);
/// The context a buyer signs its requests under.
const CONTEXT: &[u8] = b"apogee/amazon/purchase/v1";

/// A user's name, its key in the users table: K's first 32 bytes, K the key
/// digest of its Falcon-512 public key.
type Address = [u8; 32];

#[derive(Clone, Copy, PartialEq, Eq)]
struct User {
    address: Address,
    balance: U256,
    nonce: u64,
}

impl User {
    fn decode(b: &[u8]) -> User {
        User {
            address: b[..32].try_into().expect("32 bytes"),
            balance: u256_at(b, 32),
            nonce: u64_at(b, 64),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Listing {
    id: u32,
    seller: Address,
    item: u64,
    price: U256,
    stock: u64,
}

impl Listing {
    fn decode(b: &[u8]) -> Listing {
        Listing {
            id: u32_at(b, 0),
            seller: b[4..36].try_into().expect("32 bytes"),
            item: u64_at(b, 36),
            price: u256_at(b, 44),
            stock: u64_at(b, 76),
        }
    }
}

/// A table's record, which its trie holds as its key's leaf.
trait Record: Copy + PartialEq {
    /// Sets the record's leaf at its key in `trie`, its table's.
    fn write(&self, trie: &mut Trie<'_>);
}

impl Record for User {
    fn write(&self, trie: &mut Trie<'_>) {
        let mut value = [0u8; USER - 32];
        value[..32].copy_from_slice(&self.balance.to_le_bytes());
        value[32..].copy_from_slice(&self.nonce.to_le_bytes());
        trie.set(&self.address, mpt::leaf(&self.address, &value));
    }
}

impl Record for Listing {
    fn write(&self, trie: &mut Trie<'_>) {
        let key = self.id.to_be_bytes();
        let mut value = [0u8; LISTING];
        value[..32].copy_from_slice(&self.seller);
        value[32..40].copy_from_slice(&self.item.to_le_bytes());
        value[40..72].copy_from_slice(&self.price.to_le_bytes());
        value[72..].copy_from_slice(&self.stock.to_le_bytes());
        trie.set(&key, mpt::leaf(&key, &value));
    }
}

/// A record the batch reads: as the advice opened it, as the batch leaves it,
/// and whether the batch has read it yet.
struct Held<R> {
    opened: R,
    now: R,
    read: bool,
}

impl<R: Copy> Held<R> {
    fn new(record: R) -> Held<R> {
        Held {
            opened: record,
            now: record,
            read: false,
        }
    }
}

struct Request {
    buyer: Address,
    listing: u32,
    quantity: u64,
    max_price: U256,
    nonce: u64,
    market: u64,
}

impl Request {
    fn decode(b: &[u8]) -> Request {
        Request {
            buyer: b[..32].try_into().expect("32 bytes"),
            listing: u32_at(b, 32),
            quantity: u64_at(b, 36),
            max_price: u256_at(b, 44),
            nonce: u64_at(b, 76),
            market: u64_at(b, 84),
        }
    }
}

/// The working set: every record the advice holds, as opened and as the
/// requests so far leave it, each user's key once the user has signed, and
/// the volume so far.
struct Store {
    users: Vec<Held<User>>,
    keys: Vec<Option<Box<PublicKey>>>,
    listings: Vec<Held<Listing>>,
    volume: U256,
}

impl Store {
    /// The advised records, `users` of 72 bytes each and `listings` of 84.
    fn new(users: &[u8], listings: &[u8]) -> Store {
        let users: Vec<Held<User>> = users
            .chunks_exact(USER)
            .map(|b| Held::new(User::decode(b)))
            .collect();
        Store {
            keys: users.iter().map(|_| None).collect(),
            users,
            listings: listings
                .chunks_exact(4 + LISTING)
                .map(|b| Held::new(Listing::decode(b)))
                .collect(),
            volume: U256::ZERO,
        }
    }

    /// The advice's next request, from `at`, settled against the working set:
    /// the records it changes changed there. The request is valid, and the
    /// entries after it, its buyer's key at the buyer's first request and then
    /// its signature, are the buyer's, `at` moved past them all, or a panic,
    /// or the decode call's refusal.
    fn settle(&mut self, market: u64, advice: &[u8], at: &mut usize) {
        let message = take(advice, at, REQUEST);
        let r = Request::decode(message);
        assert!(r.market == market, "amazon: a request for another market");
        let b = find(&mut self.users, &r.buyer, |h| &h.opened.address);
        let buyer = self.users[b].now;
        assert!(
            r.nonce == buyer.nonce,
            "amazon: a request not at its buyer's nonce"
        );
        let next = r
            .nonce
            .checked_add(1)
            .expect("amazon: a request at the last nonce");
        // The key is read at the buyer's first request, decoded and checked
        // against the buyer's address, and kept; the signature verifies under
        // it, or the execution ends.
        let key = self.keys[b].get_or_insert_with(|| {
            let key = PublicKey::decode(take(advice, at, KEY_BYTES));
            assert!(
                key.address() == r.buyer,
                "amazon: an advised key is not its buyer's"
            );
            Box::new(key)
        });
        *at += key.verify(message, &advice[*at..], CONTEXT);
        self.users[b].now.nonce = next;

        let l = find(&mut self.listings, &r.listing, |h| &h.opened.id);
        let listing = self.listings[l].now;
        assert!(
            (1..=listing.stock).contains(&r.quantity),
            "amazon: a quantity of 0 or more than the stock"
        );
        assert!(
            listing.price <= r.max_price,
            "amazon: a price above the max price"
        );
        assert!(
            listing.seller != r.buyer,
            "amazon: a purchase of the buyer's own listing"
        );
        let cost = listing
            .price
            .checked_mul(U256::from(r.quantity))
            .expect("amazon: a cost past 2^256");
        assert!(
            cost <= buyer.balance,
            "amazon: a cost above the buyer's balance"
        );
        let s = find(&mut self.users, &listing.seller, |h| &h.opened.address);
        let seller = self.users[s].now;
        let paid = seller
            .balance
            .checked_add(cost)
            .expect("amazon: the seller's balance past 2^256");
        let volume = self
            .volume
            .checked_add(cost)
            .expect("amazon: the volume past 2^256");
        self.users[b].now.balance = buyer.balance - cost;
        self.users[s].now.balance = paid;
        self.listings[l].now.stock = listing.stock - r.quantity;
        self.volume = volume;
    }
}

/// Where the record `name` names is in `held`, which ascends by `name_of`,
/// the record marked read; or a panic: the batch reads a record the advice
/// does not hold.
fn find<R, K: Ord>(held: &mut [Held<R>], name: &K, name_of: impl Fn(&Held<R>) -> &K) -> usize {
    let i = held
        .binary_search_by(|h| name_of(h).cmp(name))
        .expect("amazon: the advice does not hold a record the batch reads");
    held[i].read = true;
    i
}

/// `held`'s records written back to `trie`, their table's, each the batch
/// changed set at its key; or a panic, for a record the batch did not read.
fn write_back<R: Record>(held: &[Held<R>], trie: &mut Trie<'_>) {
    for h in held {
        assert!(
            h.read,
            "amazon: the advice holds a record the batch does not read"
        );
        if h.now != h.opened {
            h.now.write(trie);
        }
    }
}

fn main() {
    let input = guest_sdk::public_input();
    assert!(
        input.len() == INPUT,
        "amazon: the public input is not the snapshot and the market"
    );
    let before = digest_at(input, 0);
    let market = u64_at(input, 64);

    let advice = guest_sdk::advice();
    let mut at = 0;
    let user_records = records(advice, &mut at, USER);
    let listing_records = records(advice, &mut at, 4 + LISTING);
    // A user's key is its address where the advice holds it; a listing's is
    // its id big-endian, held here as long as the trie that borrows it.
    let ids: Vec<[u8; 4]> = listing_records
        .chunks_exact(4 + LISTING)
        .map(|b| u32_at(b, 0).to_be_bytes())
        .collect();
    let mut users = Trie::open(
        32,
        user_records
            .chunks_exact(USER)
            .map(|b| (&b[..32], mpt::leaf(&b[..32], &b[32..]))),
        advice,
        &mut at,
    );
    let mut listings = Trie::open(
        4,
        ids.iter()
            .zip(listing_records.chunks_exact(4 + LISTING))
            .map(|(id, b)| (&id[..], mpt::leaf(id, &b[4..]))),
        advice,
        &mut at,
    );
    assert!(
        poseidon2_compress(&users.root(), &listings.root()) == before,
        "amazon: the advised records do not open the snapshot"
    );

    let mut store = Store::new(user_records, listing_records);
    let n = u32_at(take(advice, &mut at, 4), 0);
    for _ in 0..n {
        store.settle(market, advice, &mut at);
    }
    assert!(
        at == advice.len(),
        "amazon: the advice runs past its last signature"
    );
    write_back(&store.users, &mut users);
    write_back(&store.listings, &mut listings);
    let after = poseidon2_compress(&users.root(), &listings.root());

    let mut out = [0u8; JOURNAL];
    for (i, lane) in before.lanes().iter().chain(after.lanes()).enumerate() {
        out[8 * i..8 * i + 8].copy_from_slice(&lane.to_le_bytes());
    }
    out[128..132].copy_from_slice(&n.to_le_bytes());
    out[132..].copy_from_slice(&store.volume.to_le_bytes());
    guest_sdk::commit(&out);
}

/// The next table's records: a u32 count, then that many of `width` bytes; or
/// a panic.
fn records<'a>(advice: &'a [u8], at: &mut usize, width: usize) -> &'a [u8] {
    let count = u32_at(take(advice, at, 4), 0) as usize;
    take(advice, at, count * width)
}

/// The next `n` advised bytes, or a panic.
fn take<'a>(advice: &'a [u8], at: &mut usize, n: usize) -> &'a [u8] {
    let bytes = advice
        .get(*at..*at + n)
        .expect("amazon: the advice ended early");
    *at += n;
    bytes
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
