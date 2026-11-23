#![no_std]
#![no_main]
//! Settles a store's purchases, each signed by its buyer with Falcon-512,
//! against its two tables. It proves that the requests, each at its buyer's
//! nonce for this market and applied in the batch's order, take the snapshot
//! before to the snapshot after. The requests and their signatures are advice:
//! the journal does not name them.
//!
//! **Tables** (`docs/guest-program-manual.md` §3.3): crit-bit tries, users
//! keyed by address and listings by id, a record's leaf [`mpt::record_leaf`]
//! of its bytes, key first; the snapshot is [`poseidon2_compress`] of the
//! users root and the listings root. An address is the first 32 bytes of K,
//! the key digest of a Falcon-512 public key (`docs/spec/precompiles.md`
//! §7.7). Widths are fixed, as a leaf binds neither length; amounts are
//! [`U256`]s, and integers are little-endian except a listing's id, which is
//! big-endian as the listings' key, so the trie orders listings by id.
//!
//! ```text
//! user     72 B  address, balance U256, nonce u64
//! listing  88 B  id u64, item u64, seller address, price U256, stock u64
//! request  96 B  buyer address, max price U256, quantity u64, nonce u64,
//!                market u64, listing id u64
//! places   12 B  a request's buyer's, listing's and seller's, u32 each
//! ```
//!
//! A buyer signs its request, all 96 bytes, under the context
//! `apogee/amazon/purchase/v3`. A place is a record's index among its table's
//! advised records.
//!
//! **Public input**, exactly 72 bytes: the snapshot before, 8 `u64` lanes each
//! below `p`, then the market, `u64`.
//!
//! **Advice**, in this order, unpadded:
//! ```text
//! counts           requests n, users, listings: u32 each
//! user records     each user the batch reads, once, ascending by address
//! listing records  each listing the batch reads, once, ascending by id
//! requests         the n requests, in the batch's order
//! places           each request's places, in the same order
//! users proof      the users trie's batched proof of those addresses
//! listings proof   the listings trie's, of those ids
//! stream           per request: its buyer's key if this is the buyer's
//!                  first request, then its signature
//! ```
//!
//! Proofs are `tools/mpt`'s `Trie::proof`; keys (896 bytes) and signatures are
//! the SDK's advised forms, from `tools/falcon512`'s `key_advice` and
//! `signature_advice`.
//!
//! **Journal**, 164 bytes: the snapshots before and after, as in the input,
//! then the purchases (`u32`, n) and the volume (`U256`, the costs' sum).
//!
//! **A request applies** if its market is the input's, its nonce is its
//! buyer's and below `2^64 − 1`, its signature verifies under its buyer's key,
//! `1 ≤ quantity ≤ stock`, `price ≤ max price`, the seller is not the buyer,
//! and `cost = price · quantity` is below `2^256`, at most the buyer's balance,
//! and takes neither the seller's balance nor the volume to `2^256`. It spends
//! the nonce, moves the cost from buyer to seller, takes the quantity from the
//! stock and adds the cost to the volume. No key is inserted or removed.
//!
//! **Specialization.** The guest checks the key at each advised place instead
//! of searching, edits the records in place in the writable advice, every
//! field an aligned `u64` or four, and writes each back to its trie by its
//! place ([`Trie::set_opened`]). Past the counts, every record and request
//! lies on 8 bytes and the places on a word.
//!
//! **Strictness.** An invalid request, or advice out of the order and forms
//! above, ends the execution: a panic, or the decode call's refusal of a
//! malformed key or signature. That includes a place naming another record or
//! none, a record the batch does not read, records or proofs that do not open
//! the snapshot before, and a byte past the last signature.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::{self, MaybeUninit};

use guest_sdk::falcon512::{PublicKey, KEY_BYTES};
use guest_sdk::mpt::{self, Trie};
use guest_sdk::{poseidon2_compress, Digest, U256};

guest_sdk::entry!(main);

/// A user's record, in `u64`s: its address, its balance and its nonce.
const USER: usize = 9;
/// A listing's record, in `u64`s: its id, item, seller, price and stock.
const LISTING: usize = 11;
/// A request, in `u64`s: the bytes its buyer signs.
const REQUEST: usize = 12;
/// A request's places, in `u32`s: its buyer's, listing's and seller's.
const PLACES: usize = 3;
/// The advice's counts, in `u32`s: requests, users, listings.
const COUNTS: usize = 3;
const INPUT: usize = 72;
const JOURNAL: usize = 164;

// The advice's bytes start 4 bytes in, past its length word, so past the
// counts each record and request lies on 8 bytes, and the places after them
// on a word, as are keys.
const _: () = assert!((4 + 4 * COUNTS).is_multiple_of(8) && KEY_BYTES.is_multiple_of(4));
/// The context a buyer signs its requests under.
const CONTEXT: &[u8] = b"apogee/amazon/purchase/v3";

/// A user's record where the advice holds it: the address in `u64`s 0 to 3,
/// the balance from [`BALANCE`], the nonce in [`NONCE`].
type User = [u64; USER];
/// A listing's: its id (big-endian) in `u64` 0, item 1, the seller from
/// [`SELLER`], the price from [`PRICE`], the stock in [`STOCK`].
type Listing = [u64; LISTING];
/// A request's: buyer in `u64`s 0–3, max price 4–7, quantity 8, nonce 9,
/// market 10, listing id (big-endian) 11.
type Request = [u64; REQUEST];

const BALANCE: usize = 4;
const NONCE: usize = 8;
const SELLER: usize = 2;
const PRICE: usize = 6;
const STOCK: usize = 10;

/// A record's key, held apart for the trie to borrow while the records change.
#[repr(align(8))]
struct Key<const N: usize>([u8; N]);

/// [`Trie::open`]'s entries: each record's key and its leaf, packed in place.
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

/// The batch's state: the records in place and their marks, each user's key
/// once decoded, the arena's free slots, and the volume so far.
struct Store<'r> {
    users: &'r mut [User],
    listings: &'r mut [Listing],
    users_marked: Vec<bool>,
    listings_marked: Vec<bool>,
    keys: Vec<Option<&'static PublicKey>>,
    slots: &'static mut [MaybeUninit<PublicKey>],
    volume: U256,
}

impl Store<'_> {
    /// Applies request `r`, its places `places`, to the records in place,
    /// marking each it writes; reads the buyer's key (at its first request)
    /// and the signature of `message`, `r`'s bytes, from `stream` at `at`,
    /// moving `at` past. Panics, or the decode call refuses, unless the
    /// request applies.
    fn settle(
        &mut self,
        market: u64,
        r: &Request,
        places: &[u32; PLACES],
        message: &[u8],
        stream: &[u8],
        at: &mut usize,
    ) {
        assert!(r[10] == market, "amazon: a request for another market");
        let b = places[0] as usize;
        let buyer = &self.users[b];
        assert!(
            address_is(buyer, r),
            "amazon: a buyer's place names another user"
        );
        assert!(
            r[9] == buyer[NONCE],
            "amazon: a request not at its buyer's nonce"
        );
        let next = r[9]
            .checked_add(1)
            .expect("amazon: a request at the last nonce");
        // The buyer's key, decoded into the next slot at its first request,
        // checked against its address and kept.
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

        let l = places[1] as usize;
        let listing = &self.listings[l];
        assert!(
            listing[0] == r[11],
            "amazon: a listing's place names another listing"
        );
        let (quantity, stock) = (r[8], listing[STOCK]);
        assert!(
            quantity != 0 && quantity <= stock,
            "amazon: a quantity of 0 or more than the stock"
        );
        let price = u256_at(listing, PRICE);
        assert!(
            price <= u256_at(r, 4),
            "amazon: a price above the max price"
        );
        assert!(
            !address_is(&listing[SELLER..], r),
            "amazon: a purchase of the buyer's own listing"
        );
        let cost = price
            .checked_mul(U256::from(quantity))
            .expect("amazon: a cost past 2^256");
        let balance = u256_at(&self.users[b], BALANCE);
        assert!(cost <= balance, "amazon: a cost above the buyer's balance");
        let s = places[2] as usize;
        let seller = &self.users[s];
        assert!(
            address_is(seller, &listing[SELLER..]),
            "amazon: a seller's place names another user"
        );
        let paid = u256_at(seller, BALANCE)
            .checked_add(cost)
            .expect("amazon: the seller's balance past 2^256");
        let volume = self
            .volume
            .checked_add(cost)
            .expect("amazon: the volume past 2^256");
        set_u256(&mut self.users[b], BALANCE, balance - cost);
        set_u256(&mut self.users[s], BALANCE, paid);
        self.listings[l][STOCK] = stock - quantity;
        self.volume = volume;
        self.users_marked[s] = true;
        self.listings_marked[l] = true;
    }
}

/// Sets each record's leaf in its table's `trie` by its place; panics on a
/// record the batch did not mark, which it did not read.
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

    // The advice: counts, records (edited in place), requests, places, proofs,
    // stream.
    let (counts, records) = guest_sdk::advice_mut().split_at_mut(4 * COUNTS);
    let counts = guest_sdk::as_u32s(counts);
    let n = counts[0] as usize;
    let (users, records) = records.split_at_mut(8 * USER * counts[1] as usize);
    let (listings, rest) = records.split_at_mut(8 * LISTING * counts[2] as usize);
    let rest: &'static [u8] = rest;
    let (requests, rest) = rest.split_at(8 * REQUEST * n);
    let (places, rest) = rest.split_at(4 * PLACES * n);
    let users = guest_sdk::as_u64s_mut(users).as_chunks_mut::<USER>().0;
    let listings = guest_sdk::as_u64s_mut(listings)
        .as_chunks_mut::<LISTING>()
        .0;
    let signed = guest_sdk::as_u64s(requests).as_chunks::<REQUEST>().0;
    let places = guest_sdk::as_u32s(places).as_chunks::<PLACES>().0;

    // Each record's key: a user's address, a listing's id, its first 8 bytes.
    let mut user_keys = Vec::with_capacity(users.len());
    let mut i = 0;
    while i < users.len() {
        user_keys.push(Key(address_bytes(&users[i])));
        i += 1;
    }
    let mut listing_keys = Vec::with_capacity(listings.len());
    let mut i = 0;
    while i < listings.len() {
        listing_keys.push(Key(listings[i][0].to_le_bytes()));
        i += 1;
    }
    let mut at = 0;
    let mut user_trie = Trie::open(32, Entries::new(&user_keys, users), rest, &mut at);
    let mut listing_trie = Trie::open(8, Entries::new(&listing_keys, listings), rest, &mut at);
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
        volume: U256::ZERO,
    };
    let mut i = 0;
    while i < n {
        let message = &requests[8 * REQUEST * i..][..8 * REQUEST];
        store.settle(market, &signed[i], &places[i], message, rest, &mut at);
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

/// The `U256` in `r`'s `u64`s `i` to `i + 3`, its limbs, the low first.
#[inline(always)]
fn u256_at(r: &[u64], i: usize) -> U256 {
    U256([r[i], r[i + 1], r[i + 2], r[i + 3]])
}

/// `v`'s limbs into `r`'s `u64`s `i` to `i + 3`, the low first.
#[inline(always)]
fn set_u256(r: &mut [u64], i: usize, v: U256) {
    r[i] = v.0[0];
    r[i + 1] = v.0[1];
    r[i + 2] = v.0[2];
    r[i + 3] = v.0[3];
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

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("eight bytes"))
}

/// The digest at `at`; panics on a lane at or above `p`.
fn digest_at(b: &[u8], at: usize) -> Digest {
    Digest::new(core::array::from_fn(|i| u64_at(b, at + 8 * i)))
        .expect("amazon: a digest's lane is not below p")
}
