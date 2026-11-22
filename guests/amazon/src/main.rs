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
//! **Each record opened once, and edited where it lies.** The advice holds
//! every record the batch reads and no other, each once, the users in
//! ascending address order and the listings in ascending id order, and each
//! table's batched proof of their keys. [`Trie::open`] reads a table's pruned
//! trie from its records' leaves, each [`mpt::record_leaf`] of the record
//! where the advice holds it, and its proof, and the two roots, [`Trie::root`]
//! each, compressed, must be the snapshot: every record is held to the
//! snapshot before the batch reads it. The batch then reads and writes the
//! records where they lie, the advice being writable RAM
//! ([`guest_sdk::advice_mut`]): a purchase moves the buyer's and the seller's
//! balances and the listing's stock there, however many purchases touch them,
//! so a seller may spend later in the batch what it earned earlier in it. A
//! record the batch reads it also writes, the buyer's nonce, the listing's
//! stock and the seller's balance, and marks. After the batch each marked
//! record's leaf is packed again from it where it lies and set in its trie by
//! its place among the records, [`Trie::set_opened`], with no walk, and the
//! two roots give the snapshot after.
//!
//! **The backend finds, the guest checks.** The app's backend, which builds
//! the batch, knows where each record lies in the advice, so each request
//! carries its buyer's, its listing's and the listing's seller's places among
//! the records, and the guest checks the key at each place, an address in four
//! `u64` compares or an id in one. A place that names another record is a
//! panic, with no search and no fallback. The places are advice and not
//! signed: any other place names a record whose key fails its check.
//!
//! **Fields on their `u64`s.** Every record and request is a whole number of
//! `u64`s, its fields ordered by width after the key so that each `u64` and
//! `u128` lies on 8 bytes, and the advice puts each record and request on 8
//! bytes: a field is read with `ld` and written with `sd` where it lies
//! ([`guest_sdk::as_u64s`]), never assembled from bytes. Balances, prices and
//! the volume are `u128`.
//!
//! **Users by address.** A user is named by its address, 256 bits: the first
//! 32 bytes of K, the key digest of its Falcon-512 public key
//! (`docs/spec/precompiles.md` §7.7), and its address is its key in the users
//! table. A request names its buyer by address, and a listing its seller.
//!
//! **Signed requests.** A request's first 76 bytes are exactly the message its
//! buyer signs with Falcon-512 under the context `apogee/amazon/purchase/v2`,
//! the buyer's address, its nonce and the store's market id inside it, so a
//! request spends its nonce at most once, and in one store. A user's key is
//! advised where the user first signs, ahead of that request's signature, and
//! read there: decoded into the next slot of one arena of keys,
//! [`PublicKey::decode_into`], K computed from it, and K's address checked
//! against the buyer's, which the request's place found; then kept for the
//! user's later requests, each verified under that K. A key that does not
//! decode, or is not its buyer's, ends the execution, as does a signature that
//! does not verify: [`PublicKey::decode_into`] and [`PublicKey::verify`] are
//! the SDK's, which panic, or whose decode call refuses an encoding, rather
//! than answer a verdict. Their decoding and lattice check are the Falcon-512
//! precompiles, and K's and HashToPoint's permutations Poseidon2's.
//!
//! **The requests are advice.** The statement is that signed requests, each
//! its buyer's at that buyer's nonce, take the snapshot to the next. The
//! requests and their signatures are advice the prover chooses, so the proof
//! does not say which requests a batch settled, only that each one was signed
//! and valid for this store and snapshot: no one but its buyer can sign a
//! request. Every request in a batch applies. One that cannot, or whose
//! signature does not verify under its buyer's key, is a malformed batch, a
//! panic, never an outcome. The app's backend checks the requests and their
//! signatures and leaves out each one that cannot apply.
//!
//! **The order is the backend's.** The guest settles the requests in the
//! order the batch gives and never sorts. A buyer's nonces order its own
//! requests; the rest is the backend's policy, each listing's requests
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
//!           value  32..48   balance   u128 LE
//!                  48..56   nonce     u64: the user's next request's
//! listing   key     0..4    id        u32 big-endian
//!           value   4..8    item      u32
//!                   8..40   seller    an address
//!                  40..56   price     u128 LE: a unit's
//!                  56..64   stock     u64: the units left
//! ```
//!
//! A record is its key and then its value, 56 bytes a user's and 64 a
//! listing's, and its leaf is [`mpt::record_leaf`] of it, [`mpt::leaf`] of its
//! key and its value, one permutation of the bytes packed seven to a lane, fed
//! forward; a table's root is its trie's, the trie precompile's hash of it
//! (`docs/spec/precompiles.md`'s MPT section). A leaf binds neither length,
//! and each table's keys are one length and its values one width. A listing's
//! key is its id big-endian, so the trie's order, its keys' byte order, is the
//! ids'.
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
//! requests        u32 n: the batch's
//! users           u32: the users the batch reads
//! listings        u32: the listings it reads
//! user records    each user the batch reads, in ascending address order, 56 bytes
//! listing records each listing it reads, in ascending id order, 64 bytes
//! requests        each request, in the batch's order, 88 bytes
//! users proof     the users table's batched proof of the users above
//! listings proof  the listings table's, of the listings above
//! stream          for each request in turn: at its buyer's first, the buyer's
//!                         public key, h's 896 bytes; then the request's signature,
//!                         its 40-byte salt and s2 compressed through the word
//!                         holding its last bit
//!
//! request    0..32   buyer      an address
//!           32..48   max price  u128 LE: the most the buyer pays a unit
//!           48..56   quantity   u64
//!           56..64   nonce      u64: the buyer's
//!           64..72   market     u64: the store the buyer signed for
//!           72..76   listing    a listing's key: its id, big-endian
//!           76..80   buyer's    u32: its place among the user records
//!           80..84   listing's  u32: its place among the listing records
//!           84..88   seller's   u32: the listing's seller's among the user records
//! ```
//!
//! The buyer signs a request's first 76 bytes; its three places are the
//! backend's. The advice is these entries and nothing more: a byte after the
//! last signature is a panic.
//!
//! The advice region's bytes start 4 bytes in, past its length word, so past
//! the three counts they are on 8 bytes, and every record and request, a whole
//! number of `u64`s with no padding, starts on 8 bytes, each `u64` and `u128`
//! field too. The proofs and the stream are whole words, so each proof, each
//! key, each signature and its compressed `s2`, 40 bytes in, start on a word:
//! the trie precompile reads a proof's digests in place, the decode call and
//! the Falcon-512 precompile read keys and signatures in place, a word at a
//! time, and K and HashToPoint absorb them, and a request's signed bytes, a
//! word at a time. A key and a signature are the SDK's advised forms, v1.2's
//! encodings without their headers and the signature's padding: a key is 896
//! bytes, and a signature `40 + 4·⌈end/32⌉`, `end` the bit after its last
//! coefficient, which the decode call finds, the bits after it in its last
//! word zeros, which the call checks. The cursor moves past a signature by
//! the length [`PublicKey::verify`] returns. No byte of the advice is padding.
//!
//! A table's keys ascend strictly, which [`Trie::open`] checks, so no record is
//! advised twice. A proof is the siblings' depths and owners, then their
//! digests, each read by the precompile lane by lane mod `p`: a sibling's
//! encoding is the prover's, and no root depends on it. The records are the
//! snapshot's, before the batch, and one the batch does not read is a panic.
//! The stream is read a request at a time, so it holds a key for each user
//! that buys, at its first request, and a signature for each request: a key
//! or a signature missing, or one more, shifts every read after it, which a
//! key's decoding or address, a signature's decoding or verification, or the
//! advice's end refuses.
//!
//! # The batch
//!
//! Each request in turn, against the records as the requests before it left
//! them. Its market is the public input's; its buyer's place names a user
//! whose address is the buyer's, and its nonce is that user's and not
//! `2^64 − 1`, which leaves none after it; its signature, after its buyer's
//! key at the buyer's first request, verifies under the buyer's key and the
//! context; its listing's place names a listing whose id is the request's,
//! which holds the quantity, at least one unit, at a price no more than the
//! max price, for a seller who is not the buyer, at a cost,
//! `price · quantity`, below `2^128` and no more than the buyer's balance; and
//! its seller's place names a user whose address is the listing's seller, and
//! the cost takes neither that user's balance nor the batch's volume to
//! `2^128`. Otherwise the batch is malformed and the execution ends. The
//! request is **applied**: the buyer's nonce is spent, the cost moves from the
//! buyer's balance to the seller's, the quantity leaves the stock, and the
//! cost joins the volume, each where the record lies.
//!
//! A record is read where a check first needs it: the buyer's once the market
//! matches, the listing's once the nonce is spent, and the seller's once the
//! listing's terms and the buyer's balance allow the purchase. A place past the
//! records is a panic, and so, where the records are written back, is a record
//! the advice holds and the batch does not read.
//!
//! # The journal
//!
//! ```text
//!            0..64   the snapshot before the batch
//!           64..128  the snapshot after it
//!          128..132  purchases u32: n, as every request applies
//!          132..148  volume    u128 LE: the purchases' cost
//! ```
//!
//! A public input that is not 72 bytes, a request that is not valid, a place
//! that names another record or none, advice that is not exactly what the
//! batch reads, a key that does not decode or is not its buyer's, a signature
//! that does not decode or verify, a snapshot with a lane at or above `p`, and
//! records or a proof that do not open the snapshot, end the execution: a
//! panic, or for a key or a signature that is not one, the decode call's
//! refusal.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::{self, MaybeUninit};

use guest_sdk::falcon512::{PublicKey, KEY_BYTES};
use guest_sdk::mpt::{self, Trie};
use guest_sdk::{poseidon2_compress, Digest};

guest_sdk::entry!(main);

/// A user's record, in `u64`s: its address, its balance and its nonce.
const USER: usize = 7;
/// A listing's record, in `u64`s: its id and its item, its seller, its price
/// and its stock.
const LISTING: usize = 8;
/// A request, in `u64`s: the bytes its buyer signs, then its three places.
const REQUEST: usize = 11;
/// The bytes of a request its buyer signs.
const SIGNED: usize = 76;
/// The advice's counts, ahead of the records: the requests, the users and
/// the listings, a `u32` each.
const COUNTS: usize = 12;
const INPUT: usize = 72;
const JOURNAL: usize = 148;

// The advice region's bytes start 4 bytes in, past its length word, so the
// records after the counts start on 8 bytes, and so does every record and
// request after them, each a whole number of `u64`s. A request's signed bytes
// and a key are whole words, as a signature is by the SDK's form, so each
// starts on a word.
const _: () = assert!(
    (4 + COUNTS).is_multiple_of(8)
        && SIGNED.is_multiple_of(4)
        && SIGNED <= 8 * REQUEST
        && KEY_BYTES.is_multiple_of(4)
);
/// The context a buyer signs its requests under.
const CONTEXT: &[u8] = b"apogee/amazon/purchase/v2";

/// A user's record where the advice holds it: the address in `u64`s 0 to 3,
/// the balance in [`BALANCE`] and the one after, the nonce in [`NONCE`].
type User = [u64; USER];
/// A listing's: its id, big-endian, and its item in `u64` 0, the seller from
/// [`SELLER`], the price in [`PRICE`] and the one after, the stock in
/// [`STOCK`].
type Listing = [u64; LISTING];
/// A request's: the buyer in `u64`s 0 to 3, the max price in 4 and 5, the
/// quantity in 6, the nonce in 7, the market in 8, the listing's key and then
/// the buyer's place in 9, the listing's place and then the seller's in 10.
type Request = [u64; REQUEST];

const BALANCE: usize = 4;
const NONCE: usize = 6;
const SELLER: usize = 1;
const PRICE: usize = 5;
const STOCK: usize = 7;

/// A record's key, held apart from the records for the trie that borrows it,
/// as the batch writes the records where they lie.
#[repr(align(8))]
struct Key<const N: usize>([u8; N]);

/// A table's entries as [`Trie::open`] takes them: each record's key, from
/// the keys held apart, and its leaf, packed from the record where the advice
/// holds it.
struct Entries<'k, 'r, const N: usize, const W: usize> {
    keys: &'k [Key<N>],
    records: &'r [[u64; W]],
    next: usize,
}

impl<'k, 'r, const N: usize, const W: usize> Entries<'k, 'r, N, W> {
    fn new(keys: &'k [Key<N>], records: &'r [[u64; W]]) -> Entries<'k, 'r, N, W> {
        Entries {
            keys,
            records,
            next: 0,
        }
    }
}

impl<'k, const N: usize, const W: usize> Iterator for Entries<'k, '_, N, W> {
    type Item = (&'k [u8], Digest);

    #[inline(always)]
    fn next(&mut self) -> Option<(&'k [u8], Digest)> {
        let key = self.keys.get(self.next)?;
        let leaf = mpt::record_leaf(&self.records[self.next]);
        self.next += 1;
        Some((&key.0[..], leaf))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.keys.len() - self.next;
        (left, Some(left))
    }
}

/// The working set: the records where the advice holds them, which the batch
/// reads and writes there, and each record's mark, set as the batch writes
/// it; each user's key once the user has signed, in the arena's slot it was
/// decoded into, and the arena's slots not yet taken; and the volume so far.
struct Store<'r> {
    users: &'r mut [User],
    listings: &'r mut [Listing],
    users_marked: Vec<bool>,
    listings_marked: Vec<bool>,
    keys: Vec<Option<&'static PublicKey>>,
    slots: &'static mut [MaybeUninit<PublicKey>],
    volume: u128,
}

impl Store<'_> {
    /// The request `r`, `message` its signed bytes, settled against the
    /// working set: the records it changes changed where they lie and
    /// marked. The request is valid, its places name its buyer, its listing
    /// and the listing's seller, and the stream's entries from `at`, its
    /// buyer's key at the buyer's first request and then its signature, are
    /// the buyer's, `at` moved past them all; or a panic, or the decode call's
    /// refusal.
    fn settle(&mut self, market: u64, r: &Request, message: &[u8], stream: &[u8], at: &mut usize) {
        assert!(r[8] == market, "amazon: a request for another market");
        let b = (r[9] >> 32) as usize;
        let buyer = &self.users[b];
        assert!(
            address_is(buyer, r),
            "amazon: a buyer's place names another user"
        );
        assert!(
            r[7] == buyer[NONCE],
            "amazon: a request not at its buyer's nonce"
        );
        let next = r[7]
            .checked_add(1)
            .expect("amazon: a request at the last nonce");
        // The key is read at the buyer's first request, decoded into the
        // arena's next slot, checked against the buyer's address and kept;
        // the signature verifies under it, or the execution ends.
        let key = match self.keys[b] {
            Some(key) => key,
            None => {
                let (slot, slots) = mem::take(&mut self.slots)
                    .split_first_mut()
                    .expect("amazon: a slot for each user");
                self.slots = slots;
                let key: &'static PublicKey =
                    PublicKey::decode_into(take(stream, at, KEY_BYTES), slot);
                assert!(
                    address_is(key.key_digest().lanes(), r),
                    "amazon: an advised key is not its buyer's"
                );
                self.keys[b] = Some(key);
                key
            }
        };
        *at += key.verify(message, &stream[*at..], CONTEXT);
        self.users[b][NONCE] = next;
        self.users_marked[b] = true;

        let l = r[10] as u32 as usize;
        let listing = &self.listings[l];
        assert!(
            listing[0] as u32 == r[9] as u32,
            "amazon: a listing's place names another listing"
        );
        let (quantity, stock) = (r[6], listing[STOCK]);
        assert!(
            quantity != 0 && quantity <= stock,
            "amazon: a quantity of 0 or more than the stock"
        );
        let price = u128_at(listing, PRICE);
        assert!(
            price <= u128_at(r, 4),
            "amazon: a price above the max price"
        );
        assert!(
            !address_is(&listing[SELLER..], r),
            "amazon: a purchase of the buyer's own listing"
        );
        let cost = price
            .checked_mul(quantity as u128)
            .expect("amazon: a cost past 2^128");
        let balance = u128_at(&self.users[b], BALANCE);
        assert!(cost <= balance, "amazon: a cost above the buyer's balance");
        let s = (r[10] >> 32) as usize;
        let seller = &self.users[s];
        assert!(
            address_is(seller, &listing[SELLER..]),
            "amazon: a seller's place names another user"
        );
        let paid = u128_at(seller, BALANCE)
            .checked_add(cost)
            .expect("amazon: the seller's balance past 2^128");
        let volume = self
            .volume
            .checked_add(cost)
            .expect("amazon: the volume past 2^128");
        set_u128(&mut self.users[b], BALANCE, balance - cost);
        set_u128(&mut self.users[s], BALANCE, paid);
        self.listings[l][STOCK] = stock - quantity;
        self.volume = volume;
        self.users_marked[s] = true;
        self.listings_marked[l] = true;
    }
}

/// Each of `records`' leaves set in `trie`, its table's, by its place, packed
/// from the record where the batch left it; or a panic, for a record the
/// batch did not mark, which it did not read.
fn write_back<const W: usize>(records: &[[u64; W]], marked: &[bool], trie: &mut Trie<'_>) {
    let mut i = 0;
    while i < records.len() {
        assert!(
            marked[i],
            "amazon: the advice holds a record the batch does not read"
        );
        trie.set_opened(i, mpt::record_leaf(&records[i]));
        i += 1;
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

    // The advice in its parts: the records, written where they lie, then the
    // requests, the proofs and the stream, read where they lie.
    let (counts, records) = guest_sdk::advice_mut().split_at_mut(COUNTS);
    let n = u32_at(counts, 0) as usize;
    let (users, records) = records.split_at_mut(8 * USER * u32_at(counts, 4) as usize);
    let (listings, rest) = records.split_at_mut(8 * LISTING * u32_at(counts, 8) as usize);
    let rest: &'static [u8] = rest;
    let (requests, rest) = rest.split_at(8 * REQUEST * n);
    let users = guest_sdk::as_u64s_mut(users).as_chunks_mut::<USER>().0;
    let listings = guest_sdk::as_u64s_mut(listings)
        .as_chunks_mut::<LISTING>()
        .0;
    let signed = guest_sdk::as_u64s(requests).as_chunks::<REQUEST>().0;

    // Each record's key, held apart for the trie that borrows it; a user's is
    // its address, and a listing's its id big-endian, its first 4 bytes.
    let mut user_keys = Vec::with_capacity(users.len());
    let mut i = 0;
    while i < users.len() {
        user_keys.push(Key(address_bytes(&users[i])));
        i += 1;
    }
    let mut listing_keys = Vec::with_capacity(listings.len());
    let mut i = 0;
    while i < listings.len() {
        listing_keys.push(Key((listings[i][0] as u32).to_le_bytes()));
        i += 1;
    }
    let mut at = 0;
    let mut user_trie = Trie::open(32, Entries::new(&user_keys, users), rest, &mut at);
    let mut listing_trie = Trie::open(4, Entries::new(&listing_keys, listings), rest, &mut at);
    assert!(
        poseidon2_compress(&user_trie.root(), &listing_trie.root()) == before,
        "amazon: the advised records do not open the snapshot"
    );

    let (u, l) = (users.len(), listings.len());
    let mut store = Store {
        users,
        listings,
        users_marked: vec![false; u],
        listings_marked: vec![false; l],
        keys: vec![None; u],
        slots: Box::leak(Box::new_uninit_slice(u)),
        volume: 0,
    };
    let mut i = 0;
    while i < n {
        let message = &requests[8 * REQUEST * i..][..SIGNED];
        store.settle(market, &signed[i], message, rest, &mut at);
        i += 1;
    }
    assert!(
        at == rest.len(),
        "amazon: the advice runs past its last signature"
    );
    write_back(store.users, &store.users_marked, &mut user_trie);
    write_back(store.listings, &store.listings_marked, &mut listing_trie);
    let after = poseidon2_compress(&user_trie.root(), &listing_trie.root());

    let mut out = [0u8; JOURNAL];
    let mut i = 0;
    while i < 8 {
        out[8 * i..][..8].copy_from_slice(&before.lanes()[i].to_le_bytes());
        out[64 + 8 * i..][..8].copy_from_slice(&after.lanes()[i].to_le_bytes());
        i += 1;
    }
    out[128..132].copy_from_slice(&(n as u32).to_le_bytes());
    out[132..].copy_from_slice(&store.volume.to_le_bytes());
    guest_sdk::commit(&out);
}

/// Whether the address in `a`'s first four `u64`s is the one in `b`'s.
#[inline(always)]
fn address_is(a: &[u64], b: &[u64]) -> bool {
    a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3]
}

/// The `u128` in `r`'s `u64`s `i` and `i + 1`, the low first.
#[inline(always)]
fn u128_at(r: &[u64], i: usize) -> u128 {
    (r[i] as u128) | ((r[i + 1] as u128) << 64)
}

/// `v` into `r`'s `u64`s `i` and `i + 1`, the low first.
#[inline(always)]
fn set_u128(r: &mut [u64], i: usize, v: u128) {
    r[i] = v as u64;
    r[i + 1] = (v >> 64) as u64;
}

/// A user's address, its record's first four `u64`s, as its 32 bytes.
#[inline(always)]
fn address_bytes(user: &User) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&user[0].to_le_bytes());
    bytes[8..16].copy_from_slice(&user[1].to_le_bytes());
    bytes[16..24].copy_from_slice(&user[2].to_le_bytes());
    bytes[24..].copy_from_slice(&user[3].to_le_bytes());
    bytes
}

/// The next `n` bytes of `bytes`, from `at`, or a panic.
fn take<'a>(bytes: &'a [u8], at: &mut usize, n: usize) -> &'a [u8] {
    let taken = bytes
        .get(*at..*at + n)
        .expect("amazon: the advice ended early");
    *at += n;
    taken
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("four bytes"))
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("eight bytes"))
}

/// The digest at `at`, or a panic: a lane at or above `p` is a second encoding
/// of a node, which no table may be.
fn digest_at(b: &[u8], at: usize) -> Digest {
    Digest::new(core::array::from_fn(|i| u64_at(b, at + 8 * i)))
        .expect("amazon: a digest's lane is not below p")
}
