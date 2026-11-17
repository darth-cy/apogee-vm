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
//! **Each record opened once.** The advice holds every record the batch reads
//! and no other, each once, the users in ascending address order and the
//! listings in ascending slot order, and the batch runs against that working
//! set in memory, finding a record by binary search: a purchase moves the
//! buyer's and the seller's balances and the listing's stock there, however
//! many purchases touch them, so a seller may spend later in the batch what it
//! earned earlier in it. After the batch each record is checked and written
//! back once, along a Merkle path the advice holds under its table's root as
//! it then stands: one [`merkle_root`] call opens the record as the advice
//! gave it, the guest panicking where the roots differ, and a second writes
//! the record the batch left, where it differs. Nothing advised is trusted,
//! and nothing is committed before every record read is opened.
//!
//! **Users by address.** A user is named by its address, 256 bits: the first
//! 32 bytes of K, the key digest of its Falcon-512 public key
//! (`docs/spec/precompiles.md` §7.7). A user's record holds its address, a
//! request names its buyer by address and a listing its seller. The zero
//! address is no account's.
//!
//! **Signed requests.** A request is 92 bytes, exactly the message its buyer
//! signs with Falcon-512 under the context `apogee/amazon/purchase/v1`, the
//! buyer's address, its nonce and the store's market id inside it, so a
//! request spends its nonce at most once, and in one store. A user's key is
//! advised where the user first signs, ahead of that request's signature, and
//! read there: decoded, K computed from the same bytes, and K's address
//! checked against the buyer's, by which the request found the record; then
//! kept for the user's later requests, each verified under that K. A key that
//! does not decode, or is not its buyer's, ends the execution, as does a
//! signature that does not verify: [`PublicKey::decode`] and
//! [`PublicKey::verify`] are the SDK's, which panic, or whose decode call
//! refuses an encoding, rather than answer a verdict. Their decoding and
//! lattice check are the Falcon-512 precompiles, and K's and HashToPoint's
//! permutations Poseidon2's.
//!
//! **A signature decides no outcome.** The requests are the public input's,
//! but their signatures are advice, which the prover chooses, so an outcome
//! that turned on a signature would be the prover's: a valid request advised
//! a bad signature would be rejected, a censorship the statement cannot show.
//! A request that reaches its signature check carries one that verifies under
//! its buyer's key, or the batch is malformed and the execution ends, and so
//! every request whose nonce a proof spends is one its buyer signed. The
//! sequencer verifies the signatures before it batches the requests and drops
//! each request whose signature does not verify, as a rollup's block producer
//! does. What rejects a request is the public input's and the snapshot's
//! alone: its market, its buyer and its nonce.
//!
//! **Until the users are keyed by address.** The users table is `2^DEPTH`
//! slots, not yet a table keyed by address, and two assumptions stand in for
//! one: the table holds each address at most once, as the guest cannot see
//! which of two slots the advice chose for an address; and an address the
//! table does not hold cannot be proved absent. So the advice names each
//! user's slot, and a request or a listing naming an address the advice does
//! not hold makes the batch malformed, a panic: the guest cannot tell an
//! address the table lacks from one the advice left out.
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
//! user       0..32   address   4 lanes, u64 LE, each below p: K's lanes 0..4, K the key
//!                              digest of the user's Falcon-512 public key; zero in a
//!                              slot with no account
//!           32..64   balance   U256 LE
//!           64..72   nonce     u64: the user's next request's
//! listing    0..32   seller    an address, 4 lanes as a user's
//!           32..40   item      u64
//!           40..72   price     U256 LE: a unit's
//!           72..80   stock     u64: the units left
//! ```
//!
//! A record's leaf is one permutation of sixteen lanes: its address, the
//! user's or the seller's, as its four lanes; then the rest of its bytes
//! packed seven to a lane, little-endian, below `2^56 < p`, a user's balance
//! and nonce, 40 bytes, into lanes 4..10, and a listing's item, price and
//! stock, 48 bytes, into lanes 4..11; zeros; and the tag in lane 15, 1 for a
//! user and 2 for a listing: `compress(lanes 0..8, lanes 8..16)`. Each
//! packing is injective, every lane is below `p` (an address's checked as a
//! digest's, [`Digest::new`]), and a tag names its table's encoding. A user is
//! an account where its address is not zero, and only an account signs or is
//! paid. An empty slot holds the all-zero record: a user with no account, a
//! listing with no stock.
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
//! request    0..32   buyer     an address
//!           32..36   listing   u32: a listing's slot, below 2^DEPTH
//!           36..44   quantity  u64
//!           44..76   max price U256 LE: the most the buyer pays a unit
//!           76..84   nonce     u64: the buyer's
//!           84..92   market    u64: the store the buyer signed for
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
//! users           u32 count, then for each user the batch reads, in ascending address
//!                         order: its slot u32, below 2^DEPTH, its record
//! listings        u32 count, then for each listing the batch reads, in ascending slot
//!                         order: its slot u32, its record
//! signing         for each request that reaches its signature check, in the batch's
//!                         order: at its buyer's first, the buyer's public key, 897
//!                         bytes, then 3 zero bytes; then 3 zero bytes, the request's
//!                         signature, 666 bytes, 3 zero bytes
//! paths           for each user above in its order, then each listing: DEPTH siblings from
//!                 the leaf up, 64 bytes each, under its table's root as the records
//!                 before it left it
//! ```
//!
//! The advice is these entries and nothing more: a byte after the last path
//! is a panic.
//!
//! Every entry is a whole number of words, a key's 900 bytes and a
//! signature's 672 among them, so each key starts on a word, as do each
//! signature's salt and compressed `s2`, 4 and 44 bytes into its 672, and the
//! paths: the decode call and the precompile read them in place, a word at a
//! time, and K and HashToPoint absorb them a word at a time. The decode call
//! reads a key's last word whole, its 3 zero bytes included, and a signature's
//! up to the word holding its last coded bit. A pad byte that is not zero is a
//! panic.
//!
//! Addresses ascend as 32-byte strings compared from their first byte,
//! strictly, so no user is advised twice; nor is a slot, as a leaf holds its
//! record's address and two records at one slot cannot both open it. The
//! records are the snapshot's, before the batch, and one the batch does not
//! read is a panic. The signing stream is read as the batch reaches each
//! signature check, so it holds a key for each user that signs and a
//! signature for each request checked, and nothing for a user that does not
//! sign or a request rejected: a key or a signature missing, or one more,
//! shifts every read after it, which a key's header or address, a pad byte, a
//! verification, a path or the advice's end refuses. A path is read in place
//! by the precompile, a word at a time, each sibling's lanes mod `p`: a
//! sibling's encoding is the prover's, and no root depends on it.
//!
//! # The batch
//!
//! Each request in turn, against the records as the requests before it left
//! them. It is **rejected**, and changes nothing, where its market is not the
//! header's, its buyer is the zero address, no account, or its nonce is not
//! the buyer's or is `2^64 − 1`, which leaves none after it: checks of the
//! public input and of the buyer's record, which the snapshot binds, before
//! the signature's. Otherwise the request reaches its signature check and
//! reads the signing stream's next entries: at the buyer's first check its
//! key, then the request's signature, which verifies under the buyer's key
//! and the context, or the batch is malformed and the execution ends; the
//! nonce is spent, and the purchase is **applied** where the listing holds the
//! quantity, at least one unit, at a price no more than the max price, for a
//! seller who is not the buyer and has an account, an address not zero, at a
//! cost, `price · quantity`, below `2^256` and no more than the buyer's
//! balance, that takes neither the seller's balance nor the batch's volume to
//! `2^256`: the cost moves from the buyer's balance to the seller's, the
//! quantity leaves the stock, and the cost joins the volume. Otherwise it is
//! **declined**.
//!
//! A record is read where a check first needs it: the buyer's once the market
//! matches and the address is not zero, the listing's once the nonce is
//! spent, and the seller's once the listing's terms and the buyer's balance
//! allow the purchase. A record the batch reads and the advice does not hold
//! is a panic, and so, where the records are written back, is one the advice
//! holds and the batch does not read.
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
//! A malformed batch, advice that is not exactly what the batch reads, a pad
//! byte that is not zero, a key that does not decode or is not its buyer's, a
//! signature that does not verify, a digest or an advised record's address
//! with a lane at or above `p`, and a record or a path that does not open its
//! table, end the execution: a panic, or for a key or a signature that is not
//! an encoding, the decode call's refusal.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

use constants::guest_memory;
use guest_sdk::falcon512::{PublicKey, PUBLIC_KEY_BYTES, SIGNATURE_BYTES};
use guest_sdk::{merkle_root, poseidon2_compress, Digest, U256};

guest_sdk::entry!(main);

/// Each tree's depth: `2^20` slots.
const DEPTH: usize = 20;
const PATH: usize = 64 * DEPTH;
const USER: usize = 72;
const LISTING: usize = 80;
/// An advised key and its 3 zero bytes; a signature between 3 zero bytes
/// each side.
const KEY_SLOT: usize = PUBLIC_KEY_BYTES + 3;
const SIGNATURE_SLOT: usize = 3 + SIGNATURE_BYTES + 3;
const HEADER: usize = 76;
const REQUEST: usize = 92;
const JOURNAL: usize = 172;

// Every advised entry is a whole number of words, so each key starts on a
// word, as do each signature's salt and compressed `s2`, and the paths.
const _: () = assert!(
    (4 + USER).is_multiple_of(4)
        && KEY_SLOT.is_multiple_of(4)
        && (4 + LISTING).is_multiple_of(4)
        && SIGNATURE_SLOT.is_multiple_of(4)
);
const PAYLOAD: usize = guest_memory::PUBLIC_PAYLOAD_BYTES as usize;
/// As many requests as fit the public input beside its header.
const MAX_REQUESTS: usize = (PAYLOAD - HEADER) / REQUEST;
/// The context a buyer signs its requests under.
const CONTEXT: &[u8] = b"apogee/amazon/purchase/v1";
/// The tag lanes naming a user's encoding and a listing's.
const USER_TAG: u64 = 1;
const LISTING_TAG: u64 = 2;

// After a record's address, a user's balance and nonce pack into six lanes,
// and a listing's item, price and stock into seven, below the tag's lane.
const _: () = assert!((USER - 32).div_ceil(7) == 6 && (LISTING - 32).div_ceil(7) == 7);

/// A user's name: K's first 32 bytes, K the key digest of its Falcon-512
/// public key.
type Address = [u8; 32];

/// The zero address, which names no account.
const NO_ACCOUNT: Address = [0; 32];

#[derive(Clone, Copy, PartialEq, Eq)]
struct User {
    address: Address,
    balance: U256,
    nonce: u64,
}

impl User {
    fn decode(b: &[u8]) -> User {
        User {
            address: address_at(b, 0),
            balance: u256_at(b, 32),
            nonce: u64_at(b, 64),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Listing {
    seller: Address,
    item: u64,
    price: U256,
    stock: u64,
}

impl Listing {
    fn decode(b: &[u8]) -> Listing {
        Listing {
            seller: address_at(b, 0),
            item: u64_at(b, 32),
            price: u256_at(b, 40),
            stock: u64_at(b, 72),
        }
    }
}

/// A record whose leaf a tree holds.
trait Record: Copy + PartialEq {
    fn leaf(&self) -> Digest;
}

impl Record for User {
    fn leaf(&self) -> Digest {
        let mut rest = [0u8; USER - 32];
        rest[..32].copy_from_slice(&self.balance.to_le_bytes());
        rest[32..].copy_from_slice(&self.nonce.to_le_bytes());
        leaf(&self.address, &rest, USER_TAG)
    }
}

impl Record for Listing {
    fn leaf(&self) -> Digest {
        let mut rest = [0u8; LISTING - 32];
        rest[..8].copy_from_slice(&self.item.to_le_bytes());
        rest[8..40].copy_from_slice(&self.price.to_le_bytes());
        rest[40..].copy_from_slice(&self.stock.to_le_bytes());
        leaf(&self.seller, &rest, LISTING_TAG)
    }
}

/// A record's leaf, one permutation: `address`'s four lanes, then `rest`
/// packed seven bytes to a lane, zeros, and `tag` in lane 15.
fn leaf(address: &Address, rest: &[u8], tag: u64) -> Digest {
    let mut lanes = [0u64; 16];
    for (lane, eight) in lanes.iter_mut().zip(address.as_chunks::<8>().0) {
        *lane = u64::from_le_bytes(*eight);
    }
    pack(rest, &mut lanes[4..]);
    lanes[15] = tag;
    poseidon2_compress(&digest(&lanes[..8]), &digest(&lanes[8..]))
}

/// A record the batch reads: as the advice opened it, as the batch leaves it,
/// and whether the batch has read it yet.
struct Held<R> {
    slot: u32,
    opened: R,
    now: R,
    read: bool,
}

impl<R: Copy> Held<R> {
    fn new(slot: u32, record: R) -> Held<R> {
        Held {
            slot,
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

/// A request's outcome, its counter's place in the journal.
#[derive(Clone, Copy)]
enum Outcome {
    Applied,
    Declined,
    Rejected,
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
    /// The advised users and listings from `at`, or a panic.
    fn read(advice: &[u8], at: &mut usize) -> Store {
        let count = u32_at(take(advice, at, 4), 0) as usize;
        let mut users: Vec<Held<User>> = Vec::with_capacity(count);
        for _ in 0..count {
            let slot = slot_at(take(advice, at, 4));
            let user = User::decode(take(advice, at, USER));
            assert!(
                users.last().is_none_or(|h| h.opened.address < user.address),
                "amazon: the advised users do not ascend by address"
            );
            users.push(Held::new(slot, user));
        }
        let count = u32_at(take(advice, at, 4), 0) as usize;
        let mut listings: Vec<Held<Listing>> = Vec::with_capacity(count);
        for _ in 0..count {
            let slot = slot_at(take(advice, at, 4));
            assert!(
                listings.last().is_none_or(|h| h.slot < slot),
                "amazon: the advised listings do not ascend by slot"
            );
            listings.push(Held::new(slot, Listing::decode(take(advice, at, LISTING))));
        }
        Store {
            keys: users.iter().map(|_| None).collect(),
            users,
            listings,
            volume: U256::ZERO,
        }
    }

    /// The request `message` settled against the working set: the records it
    /// changes changed there. Where it gets past every rejection, the signing
    /// stream's next entries from `at`, its buyer's key at the buyer's first
    /// check and then its signature, are the buyer's, or a panic, or the
    /// decode call's refusal.
    fn settle(&mut self, message: &[u8], market: u64, advice: &[u8], at: &mut usize) -> Outcome {
        let r = Request::decode(message);
        assert!(
            (r.listing as usize) < 1 << DEPTH,
            "amazon: a slot outside its table"
        );
        if r.market != market || r.buyer == NO_ACCOUNT {
            return Outcome::Rejected;
        }
        let b = find(&mut self.users, &r.buyer, |h| &h.opened.address);
        let buyer = self.users[b].now;
        let next = match r.nonce.checked_add(1) {
            Some(next) if r.nonce == buyer.nonce => next,
            _ => return Outcome::Rejected,
        };
        // Every rejection is above, the public input's or the buyer's
        // record's. The signature is advice, so it rejects nothing: it
        // verifies under the buyer's key, or the execution ends. The key is
        // read at the buyer's first check, decoded and checked against the
        // buyer's address, and kept.
        let key = self.keys[b].get_or_insert_with(|| {
            let (bytes, pad) = take(advice, at, KEY_SLOT).split_at(PUBLIC_KEY_BYTES);
            assert!(pad == [0; 3], "amazon: a key's pad byte is not zero");
            let key = PublicKey::decode(bytes);
            assert!(
                key.address() == r.buyer,
                "amazon: an advised key is not its buyer's"
            );
            Box::new(key)
        });
        let (pad, rest) = take(advice, at, SIGNATURE_SLOT).split_at(3);
        let (signature, after) = rest.split_at(SIGNATURE_BYTES);
        assert!(
            pad == [0; 3] && after == [0; 3],
            "amazon: a signature's pad byte is not zero"
        );
        key.verify(message, signature, CONTEXT);
        self.users[b].now.nonce = next;

        let l = find(&mut self.listings, &r.listing, |h| &h.slot);
        let listing = self.listings[l].now;
        let cost = match listing.price.checked_mul(U256::from(r.quantity)) {
            Some(cost)
                if (1..=listing.stock).contains(&r.quantity)
                    && listing.price <= r.max_price
                    && listing.seller != r.buyer
                    && listing.seller != NO_ACCOUNT
                    && cost <= buyer.balance =>
            {
                cost
            }
            _ => return Outcome::Declined,
        };
        let s = find(&mut self.users, &listing.seller, |h| &h.opened.address);
        let seller = self.users[s].now;
        let (Some(paid), Some(volume)) = (
            seller.balance.checked_add(cost),
            self.volume.checked_add(cost),
        ) else {
            return Outcome::Declined;
        };
        self.users[b].now.balance = buyer.balance - cost;
        self.users[s].now.balance = paid;
        self.listings[l].now.stock = listing.stock - r.quantity;
        self.volume = volume;
        Outcome::Applied
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

/// `held`'s records written back to the tree `root`, each opened by the
/// advice's next path under the root as the records before it left it, and
/// written along it where the batch changed it: the tree the batch leaves, or
/// a panic, as for a record the batch did not read.
fn write_back<R: Record>(
    held: &[Held<R>],
    mut root: Digest,
    advice: &[u8],
    at: &mut usize,
) -> Digest {
    for h in held {
        assert!(
            h.read,
            "amazon: the advice holds a record the batch does not read"
        );
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
        for request in input[HEADER..].chunks_exact(REQUEST) {
            counts[store.settle(request, market, advice, &mut at) as usize] += 1;
        }
        let users = write_back(&store.users, users_root, advice, &mut at);
        let listings = write_back(&store.listings, listings_root, advice, &mut at);
        assert!(
            at == advice.len(),
            "amazon: the advice runs past its last path"
        );
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

/// The slot `bytes` hold, or a panic: a leaf of its table.
fn slot_at(bytes: &[u8]) -> u32 {
    let slot = u32_at(bytes, 0);
    assert!(
        (slot as usize) < 1 << DEPTH,
        "amazon: a slot outside its table"
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

/// Eight lanes of a leaf, each below `p`, as a digest.
fn digest(lanes: &[u64]) -> Digest {
    Digest::new(lanes.try_into().expect("eight lanes")).expect("a leaf's lanes are below p")
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

/// The address at `at`, or a panic: its four lanes, u64 LE, each below `p` as
/// a digest's, since a leaf reads them mod `p`.
fn address_at(b: &[u8], at: usize) -> Address {
    let lanes = core::array::from_fn(|i| if i < 4 { u64_at(b, at + 8 * i) } else { 0 });
    assert!(
        Digest::new(lanes).is_some(),
        "amazon: an address's lane is not below p"
    );
    b[at..at + 32].try_into().expect("32 bytes")
}
