//! Transactions as a block carries them — EIP-2718 bytes — decoded strictly,
//! their signing hashes rebuilt, their signers recovered.
//!
//! **Nothing here trusts a sender.** A payload carries signed transactions:
//! `tests-zkevm@v21.0.1`'s canonical stateless input has no public keys, and
//! the one ere-guests' layout carries per transaction is checked against the
//! recovered sender, never trusted. So every sender and every EIP-7702
//! authority is recovered from its signature inside the guest, and the rules
//! that make a signature acceptable are the spec's (`ethereum/execution-specs`,
//! `forks/amsterdam/transactions.py::recover_sender` and
//! `vm/eoa_delegation.py::recover_authority`), not the `ecrecover`
//! precompile's. The precompile accepts a high `s`; a transaction may not
//! (EIP-2).
//!
//! # The signing hash is the decoded items, re-wrapped
//!
//! What a signer signs is the transaction's own field list without its last
//! three items (`y_parity`/`v`, `r`, `s`), under a fresh list header — plus,
//! for an EIP-155 legacy transaction, `chain_id, 0, 0` — behind the type byte.
//! Every item here has already been decoded strictly, so its bytes are its one
//! canonical encoding, and concatenating them is exactly what re-encoding the
//! fields would produce: there is no field encoder to keep equal to the
//! decoder.
//!
//! # Recovery, and why it does not verify afterwards
//!
//! [`recover`] is `ecdsa`'s `VerifyingKey::recover_from_prehash` without its
//! last line. Upstream recovers `Q = r⁻¹·(s·R − z·G)` and then *verifies* the
//! signature against `Q` — a second scalar multiplication that cannot fail once
//! recovery succeeded, `s⁻¹·(z·G + r·Q)` being `R` by construction. The
//! reference recovery the spec and geth use, libsecp256k1's, does not
//! re-verify either. On this VM the re-verification is about half of a
//! recovery's 2.75 million guest cycles (measured: one upstream `ecrecover`,
//! 576 `EC_ADD` point operations), so it is dropped.
//! The arithmetic is k256's own — the same `lincomb`, `decompress` and
//! `invert` upstream calls, which `guests/vendor/k256` routes through the
//! `MOD_MUL` and `EC_ADD` delegations — and `crates/host/tests/canonical.rs`
//! holds it to upstream's full recovery on every real signature it has.

use alloc::vec::Vec;

use k256::elliptic_curve::ops::{LinearCombination, Reduce};
use k256::elliptic_curve::point::DecompressPoint;
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::subtle::Choice;
use k256::elliptic_curve::{Group, PrimeField};
use k256::{AffinePoint, ProjectivePoint, Scalar, U256};

use crate::rlp::{self, Item, Malformed};
use crate::{keccak, Address20, Word32};

/// EIP-7702's signing-hash magic.
const SET_CODE_MAGIC: u8 = 0x05;

/// One signed EIP-7702 authorization tuple, exactly as the transaction
/// carries it. Whether it recovers is [`authority`]'s question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorization {
    /// The chain it is for; zero means every chain. A `U256` in the spec.
    pub chain_id: Word32,
    /// The address the authority delegates to.
    pub address: Address20,
    /// The authority's nonce at signing.
    pub nonce: u64,
    /// A `U8` in the spec, so 2 to 255 decode and then fail to recover.
    pub y_parity: u8,
    pub r: Word32,
    pub s: Word32,
}

/// One transaction, decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx<'a> {
    /// 0 legacy, 1 EIP-2930, 2 EIP-1559, 3 EIP-4844, 4 EIP-7702.
    pub tx_type: u8,
    /// `None` exactly for a pre-EIP-155 legacy transaction (`v` of 27 or 28).
    pub chain_id: Option<u64>,
    pub nonce: u64,
    /// The gas price, or from type 2 on the max fee per gas.
    pub gas_price: u128,
    /// The max priority fee per gas; `Some` exactly from type 2 on.
    pub priority_fee: Option<u128>,
    pub gas_limit: u64,
    /// `None` is a contract creation, which types 3 and 4 cannot be.
    pub to: Option<Address20>,
    pub value: Word32,
    pub data: &'a [u8],
    /// EIP-2930: an address and the slots of it to warm.
    pub access_list: Vec<(Address20, Vec<Word32>)>,
    /// `Some` exactly on type 3.
    pub max_fee_per_blob_gas: Option<u128>,
    /// EIP-4844 versioned hashes, in order. Empty off type 3.
    pub blob_hashes: Vec<Word32>,
    /// EIP-7702's list, in order. Empty off type 4.
    pub authorizations: Vec<Authorization>,
    /// The recovery id's parity: `y_parity`, or derived from a legacy `v`.
    pub y_odd: bool,
    pub r: Word32,
    pub s: Word32,
    /// `keccak256` of what was signed.
    pub signing_hash: Word32,
}

/// Decode one transaction from its EIP-2718 bytes, strictly.
///
/// The first byte decides the form: at or above `0xc0` the bytes are a legacy
/// transaction's RLP list and nothing else; 1 to 4 is a typed transaction whose
/// remaining bytes are exactly one list; anything else — the empty string
/// included, which the spec refuses by name — is not a transaction.
pub fn decode(bytes: &[u8]) -> Result<Tx<'_>, Malformed> {
    match *bytes.first().ok_or(Malformed)? {
        0xc0..=0xff => legacy(bytes),
        tx_type @ 1..=4 => typed(tx_type, &bytes[1..]),
        _ => Err(Malformed),
    }
}

/// A legacy transaction: `[nonce, gas_price, gas, to, value, data, v, r, s]`.
fn legacy(bytes: &[u8]) -> Result<Tx<'_>, Malformed> {
    let items = rlp::list_items(bytes)?;
    if items.len() != 9 {
        return Err(Malformed);
    }
    // `v` is a `U256` in the spec: 27 or 28 is a pre-EIP-155 signature,
    // `35 + 2·chain_id + parity` an EIP-155 one, and anything else is refused.
    // A chain id that does not fit a `u64` is refused too, the spec's `chain_id`
    // being a `U64`; such a `v` needs more than 16 bytes, so `u128_of` covers it.
    let v = rlp::u128_of(&items[6])?;
    let (chain_id, y_odd) = match v {
        27 | 28 => (None, v == 28),
        35.. => {
            let chain_id = u64::try_from((v - 35) >> 1).map_err(|_| Malformed)?;
            (Some(chain_id), (v - 35) & 1 == 1)
        }
        _ => return Err(Malformed),
    };
    let mut unsigned = signed_items(&items[..6]);
    if let Some(chain_id) = chain_id {
        rlp::encode_u64(&mut unsigned, chain_id);
        unsigned.extend_from_slice(&[0x80, 0x80]);
    }
    let mut preimage = Vec::with_capacity(unsigned.len() + 9);
    rlp::encode_list(&mut preimage, &unsigned);
    Ok(Tx {
        tx_type: 0,
        chain_id,
        nonce: rlp::u64_of(&items[0])?,
        gas_price: rlp::u128_of(&items[1])?,
        priority_fee: None,
        gas_limit: rlp::u64_of(&items[2])?,
        to: to_of(&items[3])?,
        value: rlp::word_of(&items[4])?,
        data: rlp::bytes(&items[5])?,
        access_list: Vec::new(),
        max_fee_per_blob_gas: None,
        blob_hashes: Vec::new(),
        authorizations: Vec::new(),
        y_odd,
        r: rlp::word_of(&items[7])?,
        s: rlp::word_of(&items[8])?,
        signing_hash: keccak(&preimage),
    })
}

/// A typed transaction's list, after its type byte.
fn typed(tx_type: u8, body: &[u8]) -> Result<Tx<'_>, Malformed> {
    let items = rlp::list_items(body)?;
    let expected = match tx_type {
        1 => 11,
        2 => 12,
        3 => 14,
        _ => 13,
    };
    if items.len() != expected {
        return Err(Malformed);
    }
    // Types 1 and 2 put `gas_price` (or the two fee caps) where type 2 on put
    // two of them, so every later index shifts by one from type 2 on.
    let fees = if tx_type == 1 { 1 } else { 2 };
    let (gas_price, priority_fee) = if tx_type == 1 {
        (rlp::u128_of(&items[2])?, None)
    } else {
        (rlp::u128_of(&items[3])?, Some(rlp::u128_of(&items[2])?))
    };
    let at = 2 + fees;
    let to = match tx_type {
        // A blob or set-code transaction always has a destination: the spec's
        // field is an `Address`, so the empty string does not decode.
        3 | 4 => Some(rlp::fixed::<20>(&items[at + 1])?),
        _ => to_of(&items[at + 1])?,
    };
    let (max_fee_per_blob_gas, blob_hashes) = if tx_type == 3 {
        let hashes = rlp::items(&items[at + 6])?
            .iter()
            .map(rlp::fixed::<32>)
            .collect::<Result<Vec<Word32>, Malformed>>()?;
        (Some(rlp::u128_of(&items[at + 5])?), hashes)
    } else {
        (None, Vec::new())
    };
    let authorizations = if tx_type == 4 {
        rlp::items(&items[at + 5])?
            .iter()
            .map(authorization_of)
            .collect::<Result<Vec<Authorization>, Malformed>>()?
    } else {
        Vec::new()
    };
    // `y_parity` is a `U256` in the spec and anything but 0 or 1 is refused;
    // the boolean is all a caller needs.
    let n = items.len();
    let y_parity = rlp::u64_of(&items[n - 3])?;
    if y_parity > 1 {
        return Err(Malformed);
    }
    let mut preimage = Vec::with_capacity(body.len() + 1);
    preimage.push(tx_type);
    rlp::encode_list(&mut preimage, &signed_items(&items[..n - 3]));
    Ok(Tx {
        tx_type,
        chain_id: Some(rlp::u64_of(&items[0])?),
        nonce: rlp::u64_of(&items[1])?,
        gas_price,
        priority_fee,
        gas_limit: rlp::u64_of(&items[at])?,
        to,
        value: rlp::word_of(&items[at + 2])?,
        data: rlp::bytes(&items[at + 3])?,
        access_list: access_list_of(&items[at + 4])?,
        max_fee_per_blob_gas,
        blob_hashes,
        authorizations,
        y_odd: y_parity == 1,
        r: rlp::word_of(&items[n - 2])?,
        s: rlp::word_of(&items[n - 1])?,
        signing_hash: keccak(&preimage),
    })
}

/// The concatenated encodings of the signed-over items.
fn signed_items(items: &[Item<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    for item in items {
        out.extend_from_slice(item.whole);
    }
    out
}

/// A `to` field: the empty string for a creation, otherwise 20 bytes.
fn to_of(item: &Item<'_>) -> Result<Option<Address20>, Malformed> {
    match rlp::bytes(item)? {
        [] => Ok(None),
        _ => Ok(Some(rlp::fixed::<20>(item)?)),
    }
}

/// An EIP-2930 access list: `[[address, [key, ...]], ...]`.
fn access_list_of(item: &Item<'_>) -> Result<Vec<(Address20, Vec<Word32>)>, Malformed> {
    let mut out = Vec::new();
    for entry in rlp::items(item)? {
        let pair = rlp::items(&entry)?;
        if pair.len() != 2 {
            return Err(Malformed);
        }
        let keys = rlp::items(&pair[1])?
            .iter()
            .map(rlp::fixed::<32>)
            .collect::<Result<Vec<Word32>, Malformed>>()?;
        out.push((rlp::fixed::<20>(&pair[0])?, keys));
    }
    Ok(out)
}

/// One authorization tuple: `[chain_id, address, nonce, y_parity, r, s]`.
fn authorization_of(item: &Item<'_>) -> Result<Authorization, Malformed> {
    let fields = rlp::items(item)?;
    if fields.len() != 6 {
        return Err(Malformed);
    }
    let y_parity = rlp::u64_of(&fields[3])?;
    Ok(Authorization {
        chain_id: rlp::word_of(&fields[0])?,
        address: rlp::fixed::<20>(&fields[1])?,
        nonce: rlp::u64_of(&fields[2])?,
        y_parity: u8::try_from(y_parity).map_err(|_| Malformed)?,
        r: rlp::word_of(&fields[4])?,
        s: rlp::word_of(&fields[5])?,
    })
}

/// The transaction's sender, or `None` when its signature is not one a
/// transaction may carry: `0 < r < n`, `0 < s ≤ n/2`, and a point that
/// recovers.
pub fn sender(tx: &Tx<'_>) -> Option<Address20> {
    recover(&tx.signing_hash, &tx.r, &tx.s, tx.y_odd)
}

/// The EIP-7702 authority an authorization tuple names, or `None` when its
/// signature does not recover — which the transaction survives: the tuple is
/// skipped, as EIP-7702 says.
///
/// The signing hash is `keccak256(0x05 ‖ rlp([chain_id, address, nonce]))`.
pub fn authority(auth: &Authorization) -> Option<Address20> {
    if auth.y_parity > 1 {
        return None;
    }
    let mut fields = Vec::with_capacity(64);
    rlp::encode_uint(&mut fields, &auth.chain_id);
    rlp::encode_bytes(&mut fields, &auth.address);
    rlp::encode_u64(&mut fields, auth.nonce);
    let mut preimage = Vec::with_capacity(fields.len() + 2);
    preimage.push(SET_CODE_MAGIC);
    rlp::encode_list(&mut preimage, &fields);
    recover(&keccak(&preimage), &auth.r, &auth.s, auth.y_parity == 1)
}

/// [`recover_key`], to the address the key names.
pub fn recover(prehash: &Word32, r: &Word32, s: &Word32, y_odd: bool) -> Option<Address20> {
    recover_key(prehash, r, s, y_odd).map(|key| address_of(&key))
}

/// The address an uncompressed public key names: the last twenty bytes of
/// `keccak256(x ‖ y)`.
pub fn address_of(key: &[u8; 65]) -> Address20 {
    keccak(&key[1..])[12..].try_into().expect("twenty bytes")
}

/// secp256k1 public-key recovery, under the rules a transaction's and an
/// authorization's signature share: `0 < r < n`, `0 < s ≤ n/2`, and `R` — the
/// point whose `x` is `r` and whose `y` has the given parity — on the curve.
/// The key is uncompressed, `0x04 ‖ x ‖ y`.
///
/// `ecdsa`'s `recover_from_prehash` without the verification it ends on; the
/// module doc says why that is sound and what it saves.
pub fn recover_key(prehash: &Word32, r: &Word32, s: &Word32, y_odd: bool) -> Option<[u8; 65]> {
    // `from_repr` refuses a value at or above `n`.
    let r_scalar = Option::<Scalar>::from(Scalar::from_repr((*r).into()))?;
    let s_scalar = Option::<Scalar>::from(Scalar::from_repr((*s).into()))?;
    if bool::from(r_scalar.is_zero()) || bool::from(s_scalar.is_zero()) {
        return None;
    }
    // EIP-2: a high `s` is the same signature's second encoding.
    if bool::from(s_scalar.is_high()) {
        return None;
    }
    // `r < n < p`, so `r` is a field element as it stands; a recovery id of 0
    // or 1 never asks for the `r + n` x-coordinate.
    let big_r = Option::<AffinePoint>::from(AffinePoint::decompress(
        &(*r).into(),
        Choice::from(y_odd as u8),
    ))?;
    let z = <Scalar as Reduce<U256>>::reduce_bytes(&(*prehash).into());
    let r_inv = Option::<Scalar>::from(r_scalar.invert())?;
    let u1 = -(r_inv * z);
    let u2 = r_inv * s_scalar;
    let q = ProjectivePoint::lincomb(
        &ProjectivePoint::GENERATOR,
        &u1,
        &ProjectivePoint::from(big_r),
        &u2,
    );
    if bool::from(q.is_identity()) {
        return None;
    }
    let point = q.to_affine().to_encoded_point(false);
    Some(point.as_bytes().try_into().expect("an uncompressed point"))
}
