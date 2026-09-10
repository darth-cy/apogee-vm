#![no_std]
#![no_main]
//! A Merkle-gated withdrawal vault: `n` withdrawals settled in order against a
//! fixed-depth Merkle tree of balances, with ERC-4626-style share accounting
//! carried alongside.
//!
//! Balances sit at the leaves of a depth-`d` tree over the BN254 scalar field.
//! A leaf is `hash2(account, balance)` and an internal node is the hash of its
//! two children, so the root is a commitment to every balance at once. Each
//! withdrawal arrives with the sibling path that places its leaf: the guest
//! recomputes the root from the leaf upward, compares it against the running
//! root, debits the balance, recomputes the root along the same path from the
//! new leaf, and hands that root to the next withdrawal. Two withdrawals
//! against the same account therefore chain, without the guest tracking
//! accounts at all — the second must present the balance the first left behind,
//! because any other balance hashes to a leaf that does not reproduce the root
//! the first one wrote.
//!
//! # What this is a fixture for
//!
//! This repository's own `no_std` crates, running inside the proof. `guests/echo`
//! links `crates/field` and `crates/transcript` to show that they compile for
//! RV32; this one puts them under a computation with the shape a real circuit
//! has. At the format's limits — 32 withdrawals at depth 16 — it is 1,088
//! Poseidon2 permutations and one field inversion on a 32-bit machine, where
//! every Montgomery multiply is sixteen 32x32 partial products. It is the only
//! guest that inverts a field element, and `Fr::inverse` is Fermat, so that is
//! `Fr::pow` over a 254-bit exponent rather than a Euclidean loop. It is also
//! the only guest that takes the Poseidon2 precompile's software fallback in
//! anger rather than once for show, and its path walk is the deepest call chain
//! in `guests/`, which is the only thing here that puts the stack reservation
//! `link.ld` declares under any load at all.
//!
//! # fd 0, the public input
//!
//! A 104-byte header, then `n` records of `100 + depth * 32` bytes each. Every
//! 32-byte field is a canonical little-endian `Fr`.
//!
//! ```text
//! header    0..32    root            the tree root the batch opens against
//!          32..64    total_assets    the vault's assets, for the share price
//!          64..96    total_shares    the vault's shares outstanding
//!          96..100   depth           u32 LE, 1..=16
//!         100..104   n               u32 LE, at most 32
//!
//! record    0..32    account         the leaf's account identifier
//!          32..64    balance         the leaf's current balance
//!          64..96    amount          the amount to withdraw
//!          96..100   path_bits       u32 LE; bit i set means the node arriving
//!                                    at level i is the RIGHT child
//!         100..      siblings        depth * 32 bytes, level 0 — the one
//!                                    nearest the leaf — first
//! ```
//!
//! # fd 1, the public output
//!
//! 104 bytes, written once at the end:
//!
//! ```text
//!           0..32    final_root      the root after the accepted withdrawals
//!          32..64    total_withdrawn the field sum of accepted amounts
//!          64..96    shares_burned   the field sum of the shares those burned
//!          96..100   accepted        u32 LE
//!         100..104   rejected        u32 LE
//! ```
//!
//! # fd 3, and why it is empty
//!
//! Unused, and the reason is worth stating because a Merkle path is exactly the
//! shape of thing a hint channel exists for: the prover knows it, deriving it
//! costs the verifier a whole tree, and it is discarded the moment it has been
//! checked. It arrives on fd 0 regardless, because fd 0 is what the public I/O
//! digest binds. A path read from fd 3 would let the prover choose, after the
//! fact, which leaf it had proved — the root check would still pass, against a
//! leaf nobody agreed to — and the statement would degrade from "these balances
//! were debited" to "some balances were".
//!
//! # What is trusted, and what is merely public
//!
//! fd 0 is public but not well-formed by assumption; it is a byte string the
//! prover hands over. The split is between structure and content. A header that
//! is short, a depth outside `1..=16`, a batch larger than 32, or a stream that
//! ends inside a record is a malformed statement rather than a rejected
//! withdrawal — there is no batch to settle — so it panics, which fails the
//! execution loudly and prints where on fd 2. A record whose contents do not
//! satisfy the vault's rules is an ordinary rejection: it is counted, the root
//! is left alone, and the batch carries on.

use field::Fr;

guest_sdk::entry!(main);

// The heap is deliberately not used, and `guests/echo` is where the bump
// allocator is exercised. Every buffer here has a bound the format states — a
// record is at most 612 bytes and a batch at most 32 of them — so a fixed array
// says the bound in the type, and an allocator whose `dealloc` does nothing
// would leak a fresh record buffer on every iteration for no benefit.

// ---------------------------------------------------------------------------
// The format's bounds
// ---------------------------------------------------------------------------

/// The deepest tree the format allows, and therefore the recursion bound.
const MAX_DEPTH: usize = 16;

/// The largest batch the format allows.
const MAX_WITHDRAWALS: u32 = 32;

/// `root`, `total_assets`, `total_shares`, `depth`, `n`.
const HEADER_LEN: usize = 104;

/// A record's fixed part: `account`, `balance`, `amount`, `path_bits`. The
/// siblings follow and are `depth * 32` bytes long.
const RECORD_FIXED_LEN: usize = 100;

/// The largest record: the fixed part plus siblings at `MAX_DEPTH`.
const MAX_RECORD_LEN: usize = RECORD_FIXED_LEN + MAX_DEPTH * 32;

/// `final_root`, `total_withdrawn`, `shares_burned`, `accepted`, `rejected`.
const OUTPUT_LEN: usize = 104;

/// Status for a precompile that reported success and returned a state lane that
/// is not a field element. It continues `crates/guest-sdk`'s 70-72 series of
/// executor-fault codes without colliding with one.
const EXIT_PRECOMPILE_NONCANONICAL: i32 = 73;

// ---------------------------------------------------------------------------
// The hash
// ---------------------------------------------------------------------------

/// The tree's compression function: permute `[a, b, 0]` and take lane 0.
///
/// The permutation is asked of the executor first, as
/// `constants::ecall::PRECOMPILE_POSEIDON2` over the 96-byte canonical
/// little-endian state, and computed with `transcript::poseidon2_permute` when
/// the executor answers `false` — which every executor does today, because the
/// precompile has a number and a calling convention but no circuit behind it.
/// **The software path is the one the proof is about**, and stays so until a
/// delegation circuit exists; the ecall is here so that on the day one does,
/// this guest already speaks to it and its committed output does not move.
///
/// A precompile that reports success and hands back a lane outside `[0, p)` has
/// broken its own contract, and that is an executor fault rather than a
/// malformed input. It exits nonzero instead of substituting a value: carrying
/// on would mean folding something that is not a field element into a root, and
/// producing a proof of a tree nobody else can reconstruct.
fn hash2(a: Fr, b: Fr) -> Fr {
    let mut state_bytes = [0u8; 96];
    state_bytes[0..32].copy_from_slice(&a.to_bytes());
    state_bytes[32..64].copy_from_slice(&b.to_bytes());
    // The third lane is written rather than left as the zeros the buffer
    // already holds, because it is the capacity and its value is part of what
    // this hash *is*. Two-to-one compression has no domain separator to put
    // there, and a later decision to add one belongs on this line.
    state_bytes[64..96].copy_from_slice(&Fr::ZERO.to_bytes());

    if guest_sdk::poseidon2_permute(&mut state_bytes) {
        match decode_fr(&state_bytes[0..32]) {
            Some(lane) => lane,
            None => guest_sdk::exit(EXIT_PRECOMPILE_NONCANONICAL),
        }
    } else {
        let mut state = [a, b, Fr::ZERO];
        transcript::poseidon2_permute(&mut state);
        state[0]
    }
}

// ---------------------------------------------------------------------------
// The path walk
// ---------------------------------------------------------------------------

/// Fold `node` at `level` upward to the root, one hash per remaining level.
///
/// Recursive on purpose. A loop would do the identical arithmetic in one frame,
/// and part of what this guest exists to exercise is a call chain deep enough
/// to matter: at depth 16 this is sixteen nested frames above `main`, each
/// holding its own copy of the arguments because the guest profile is
/// opt-level 0 and nothing is inlined or turned into a jump. That is the only
/// stack pressure anywhere in `guests/`, and the stack is the segment `link.ld`
/// has to declare for a host loader to map it at all.
///
/// The recursion is bounded because `depth` is: the header parse rejects
/// anything outside `1..=16` before a record is read, so this cannot run away
/// on hostile input.
///
/// `bits` is read one bit per level, bit `i` for level `i`: set means the node
/// arriving at that level is the right child, so its sibling is hashed first.
/// The shift is therefore by at most 15 and cannot be the overflowing shift
/// that debug assertions trap. Bits at or above `depth` name levels that do not
/// exist; they are ignored, because they cannot change the result and refusing
/// them would be a rule the format does not state.
fn merkle_root(node: Fr, level: usize, depth: usize, bits: u32, siblings: &[Fr; MAX_DEPTH]) -> Fr {
    if level == depth {
        return node;
    }
    let sibling = siblings[level];
    let parent = if (bits >> level) & 1 == 1 {
        hash2(sibling, node)
    } else {
        hash2(node, sibling)
    };
    merkle_root(parent, level + 1, depth, bits, siblings)
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// One withdrawal, decoded.
///
/// Balances and amounts appear twice, as a field element and as an integer,
/// which [`decode_bounded`] explains.
struct Withdrawal {
    account: Fr,
    balance: Fr,
    balance_int: u128,
    amount: Fr,
    amount_int: u128,
    path_bits: u32,
    siblings: [Fr; MAX_DEPTH],
}

/// Decode a canonical little-endian field element, or `None`.
///
/// `Fr::from_bytes` refuses anything at or above the modulus rather than
/// reducing it, which is what keeps one value to one encoding — and an encoding
/// that decoded two ways would let a prover present the same balance twice with
/// different bytes.
fn decode_fr(bytes: &[u8]) -> Option<Fr> {
    let word: [u8; 32] = bytes.try_into().ok()?;
    Fr::from_bytes(&word)
}

/// Decode a quantity that has to be *ordered* as well as hashed: the field
/// element and the integer it stands for.
///
/// **A field element has no order.** `Fr` is the residues modulo `p`, and the
/// map from integers to residues wraps, so `x` and `x + p` are one element and
/// "less than" is not a property the value carries — comparing two `Fr`s would
/// be comparing representatives, and the answer would depend on which
/// representative the prover chose to send. The honest way to get an order is
/// to say in the format which integers are meant: a balance and an amount are
/// carried as field elements and read a second time as `u128`s out of the low
/// 16 bytes of that same canonical encoding, with the high 16 bytes required to
/// be zero. The comparison is then a comparison of integers below `2^128`,
/// where the map into the field is injective and order-preserving.
///
/// That bound also makes the debit exact. `2^128` is far below `p`, so for
/// `amount <= balance` the field subtraction `balance - amount` is the integer
/// difference and never a wrap around the modulus.
///
/// The width is structure and panics, as in [`decode_u32`]; only the two
/// content failures — a value at or above `p`, and a value at or above `2^128`
/// — come back as reasons a withdrawal was rejected.
fn decode_bounded(bytes: &[u8]) -> Result<(Fr, u128), &'static str> {
    let word: [u8; 32] = bytes
        .try_into()
        .expect("vault: a field element occupies 32 bytes");
    let value = Fr::from_bytes(&word).ok_or("a field element is not canonical")?;
    if word[16..].iter().any(|&b| b != 0) {
        return Err("a balance or an amount does not fit in 128 bits");
    }
    let mut low = [0u8; 16];
    low.copy_from_slice(&word[..16]);
    Ok((value, u128::from_le_bytes(low)))
}

/// Decode a little-endian `u32` field.
///
/// The length is a structural property of the format, not a claim the input
/// gets to make, so a mismatch here is a bug in this file rather than a
/// rejection: every caller slices a fixed four-byte window out of a buffer
/// whose length was already checked against the read count.
fn decode_u32(bytes: &[u8]) -> u32 {
    let word: [u8; 4] = bytes.try_into().expect("vault: a u32 field is four bytes");
    u32::from_le_bytes(word)
}

/// Decode one record, or say why it cannot be settled.
///
/// Every failure is a rejection rather than a panic. fd 0 is public but not
/// trusted to be well-formed, and a single malformed record says nothing about
/// the other thirty-one — refusing the batch over one would hand a prover a way
/// to void a settlement it did not like by corrupting a field it controls.
fn parse_record(bytes: &[u8], depth: usize) -> Result<Withdrawal, &'static str> {
    debug_assert_eq!(
        bytes.len(),
        RECORD_FIXED_LEN + depth * 32,
        "vault: parse_record was handed a record of the wrong length"
    );

    let account = decode_fr(&bytes[0..32]).ok_or("an account is not canonical")?;
    let (balance, balance_int) = decode_bounded(&bytes[32..64])?;
    let (amount, amount_int) = decode_bounded(&bytes[64..96])?;
    let path_bits = decode_u32(&bytes[96..100]);

    // Levels above `depth` keep the `ZERO` they were built with and are never
    // read: `merkle_root` stops at `depth`.
    let mut siblings = [Fr::ZERO; MAX_DEPTH];
    for (slot, chunk) in siblings[..depth]
        .iter_mut()
        .zip(bytes[RECORD_FIXED_LEN..].chunks_exact(32))
    {
        *slot = decode_fr(chunk).ok_or("a sibling is not canonical")?;
    }

    Ok(Withdrawal {
        account,
        balance,
        balance_int,
        amount,
        amount_int,
        path_bits,
        siblings,
    })
}

// ---------------------------------------------------------------------------
// The batch
// ---------------------------------------------------------------------------

/// Settle the batch: read the header, then take the withdrawals in the order
/// fd 0 presents them.
///
/// The order is the statement, not an implementation detail. Each withdrawal is
/// checked against the root its predecessors left, so the batch is a sequence of
/// tree transitions rather than a set of independent proofs, and a rejected
/// withdrawal is a transition that did not happen: the root does not move, the
/// sums do not move, and the next withdrawal sees exactly what it would have
/// seen had the rejected one never been sent. Nothing is unwound, because
/// nothing was written before every check on it had passed.
fn main() {
    let mut header = [0u8; HEADER_LEN];
    assert_eq!(
        guest_sdk::read_input(&mut header),
        HEADER_LEN,
        "vault: fd 0 ended inside the header"
    );

    // The three header field elements are the statement itself — the root the
    // batch opens against and the price it settles at — so a non-canonical one
    // is a malformed statement and not a rejected withdrawal. There is nothing
    // to reject against.
    let mut root = decode_fr(&header[0..32]).expect("vault: root is not a canonical field element");
    let total_assets =
        decode_fr(&header[32..64]).expect("vault: total_assets is not a canonical field element");
    let total_shares =
        decode_fr(&header[64..96]).expect("vault: total_shares is not a canonical field element");

    let depth = decode_u32(&header[96..100]) as usize;
    let count = decode_u32(&header[100..104]);
    assert!(
        (1..=MAX_DEPTH).contains(&depth),
        "vault: depth is outside 1..=16"
    );
    assert!(
        count <= MAX_WITHDRAWALS,
        "vault: a batch carries at most 32 withdrawals"
    );

    // One inversion for the whole batch. `Fr::inverse` is Fermat, so it is a
    // 254-bit `Fr::pow` — some 380 Montgomery multiplies, each sixteen 32x32
    // products on this machine — and doing it per withdrawal would cost more
    // than every Merkle hash in the batch put together. `total_assets` is a
    // header field and does not move as withdrawals settle, so there is nothing
    // to recompute. A vault holding no assets has no share price at all:
    // `inverse` answers `None` for zero, and every withdrawal is then rejected
    // rather than settled at a price that does not exist.
    let assets_inverse = total_assets.inverse();

    let record_len = RECORD_FIXED_LEN + depth * 32;
    let mut record = [0u8; MAX_RECORD_LEN];

    let mut accepted: u32 = 0;
    let mut rejected: u32 = 0;
    let mut total_withdrawn = Fr::ZERO;
    let mut shares_burned = Fr::ZERO;

    for index in 0..count {
        // A record has a fixed length once `depth` is known, so a short read is
        // a truncated stream and not a small batch: `count` already said how
        // many records there are, and proceeding on a partly-filled buffer
        // would settle a withdrawal against zeros.
        assert_eq!(
            guest_sdk::read_input(&mut record[..record_len]),
            record_len,
            "vault: fd 0 ended inside a withdrawal record"
        );

        let withdrawal = match parse_record(&record[..record_len], depth) {
            Ok(withdrawal) => withdrawal,
            Err(why) => {
                rejected += 1;
                log_rejection(index, why);
                continue;
            }
        };

        let Some(assets_inverse) = assets_inverse else {
            rejected += 1;
            log_rejection(
                index,
                "the vault holds no assets, so there is no share price",
            );
            continue;
        };

        // The comparison is on the integers the two encodings named, for the
        // reason `decode_bounded` gives; both are below 2^128 or the record was
        // rejected there.
        if withdrawal.amount_int > withdrawal.balance_int {
            rejected += 1;
            log_rejection(index, "the amount exceeds the balance");
            continue;
        }

        // The inclusion proof is checked against the *running* root, not the
        // header's, which is what makes the batch a sequence rather than a set:
        // a withdrawal is admitted only against the tree its predecessors left.
        let leaf = hash2(withdrawal.account, withdrawal.balance);
        let proved = merkle_root(leaf, 0, depth, withdrawal.path_bits, &withdrawal.siblings);
        if proved != root {
            rejected += 1;
            log_rejection(index, "the path does not reproduce the current root");
            continue;
        }

        // The same path and the same siblings, from a leaf carrying the debited
        // balance. Reusing the sibling list is what makes this an update rather
        // than a second proof: the siblings were just shown to be the ones the
        // old root was built from, so the new root differs from it in exactly
        // the one leaf that changed.
        let debited = hash2(withdrawal.account, withdrawal.balance - withdrawal.amount);
        root = merkle_root(
            debited,
            0,
            depth,
            withdrawal.path_bits,
            &withdrawal.siblings,
        );

        total_withdrawn += withdrawal.amount;
        shares_burned += withdrawal.amount * total_shares * assets_inverse;
        accepted += 1;
    }

    // `accepted` and `rejected` cannot overflow: they are incremented at most
    // once per iteration and the loop runs at most `MAX_WITHDRAWALS` times.
    debug_assert_eq!(
        accepted + rejected,
        count,
        "vault: every withdrawal is either accepted or rejected"
    );

    let mut out = [0u8; OUTPUT_LEN];
    out[0..32].copy_from_slice(&root.to_bytes());
    out[32..64].copy_from_slice(&total_withdrawn.to_bytes());
    out[64..96].copy_from_slice(&shares_burned.to_bytes());
    out[96..100].copy_from_slice(&accepted.to_le_bytes());
    out[100..104].copy_from_slice(&rejected.to_le_bytes());
    // One `commit`, because the journal is one record and writing it in pieces
    // would let a panic between two of them leave a half-written statement on
    // fd 1.
    guest_sdk::commit(&out);
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

/// Note a rejected withdrawal on fd 2.
///
/// The verifier ignores fd 2 entirely, so the reason can be as specific as it
/// likes without becoming part of the statement — which is the point: a reason
/// on fd 1 would be a claim the verifier has to interpret, whereas the count
/// alone is checkable by re-running the rules.
fn log_rejection(index: u32, why: &str) {
    guest_sdk::log(b"vault: rejected withdrawal ");
    log_u32(index);
    guest_sdk::log(b": ");
    guest_sdk::log(why.as_bytes());
    guest_sdk::log(b"\n");
}

/// Write `value` to fd 2 in decimal.
///
/// Longhand rather than `write!`, because `core::fmt` on fd 2 would drag the
/// formatting machinery into `.text` for a diagnostic — the panic handler is
/// welcome to it, since by then the execution has already failed.
fn log_u32(mut value: u32) {
    // Ten digits is the width of `u32::MAX`, so the index never runs past the
    // front of the buffer.
    let mut digits = [b'0'; 10];
    let mut at = digits.len();
    loop {
        at -= 1;
        digits[at] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    guest_sdk::log(&digits[at..]);
}
