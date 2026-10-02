//! RLP, strictly: the one codec the trie, the header, the transactions and the
//! receipts share.
//!
//! **Every canonical-form rule is enforced on the way in**, because each one is
//! a second encoding of one value: a one-byte string below `0x80` wrapped in a
//! header, a length that fits the short form written long, a length with a
//! leading zero, an integer with a leading zero. A trie node is bound by its
//! keccak and cannot be re-encoded under it, but a transaction, a header and
//! an ancestor are bound only by hashes *this* guest computes over the bytes it
//! was handed — so a decoder laxer than a client's would accept a block a client
//! refuses. Every decoder here is as strict as `ethereum_rlp`'s, which is what
//! the canonical validator (`ethereum/execution-specs`) decodes with.
//!
//! **Lengths are checked arithmetic.** The guest's `usize` is four bytes with
//! `overflow-checks` on in both profiles, and every length here is one the
//! input's own bytes declare, so an unchecked `+` is a panic a prover can
//! choose — and a guest that panics publishes nothing.

use alloc::vec::Vec;

use crate::Word32;

/// Bytes that are not a canonical RLP encoding of what was expected.
///
/// One error for every shape, because a caller can do nothing different about
/// any of them: the input is not the thing it claims to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Malformed;

/// One RLP item: where its payload is, and whether it is a list.
#[derive(Clone, Copy, Debug)]
pub struct Item<'a> {
    /// A list, rather than a byte string.
    pub list: bool,
    /// The payload: a string's bytes, or a list's concatenated items.
    pub payload: &'a [u8],
    /// The item's complete encoding, header included.
    pub whole: &'a [u8],
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Split one item off the front of `bytes`, strictly.
pub fn split(bytes: &[u8]) -> Result<(Item<'_>, &[u8]), Malformed> {
    let first = *bytes.first().ok_or(Malformed)?;
    match first {
        // A single byte below 0x80 is itself, with no header.
        0x00..=0x7f => Ok((
            Item {
                list: false,
                payload: &bytes[..1],
                whole: &bytes[..1],
            },
            &bytes[1..],
        )),
        0x80..=0xb7 => {
            let len = (first - 0x80) as usize;
            let body = bytes.get(1..1 + len).ok_or(Malformed)?;
            // A one-byte string below 0x80 is never wrapped.
            if len == 1 && body[0] < 0x80 {
                return Err(Malformed);
            }
            Ok((
                Item {
                    list: false,
                    payload: body,
                    whole: &bytes[..1 + len],
                },
                &bytes[1 + len..],
            ))
        }
        0xb8..=0xbf => long(bytes, (first - 0xb7) as usize, false),
        0xc0..=0xf7 => {
            let len = (first - 0xc0) as usize;
            let body = bytes.get(1..1 + len).ok_or(Malformed)?;
            Ok((
                Item {
                    list: true,
                    payload: body,
                    whole: &bytes[..1 + len],
                },
                &bytes[1 + len..],
            ))
        }
        0xf8..=0xff => long(bytes, (first - 0xf7) as usize, true),
    }
}

fn long(bytes: &[u8], width: usize, list: bool) -> Result<(Item<'_>, &[u8]), Malformed> {
    let size = bytes.get(1..1 + width).ok_or(Malformed)?;
    // No leading zero in a length, and the length must not have fitted the
    // short form.
    if size[0] == 0 {
        return Err(Malformed);
    }
    // `usize` is four bytes on the guest, so a wide length is an overflow and
    // never a silent truncation.
    if width > core::mem::size_of::<usize>() {
        return Err(Malformed);
    }
    let mut len = 0usize;
    for byte in size {
        len = len.checked_mul(256).ok_or(Malformed)?;
        len = len.checked_add(*byte as usize).ok_or(Malformed)?;
    }
    if len <= 55 {
        return Err(Malformed);
    }
    let at = 1 + width;
    let end = at.checked_add(len).ok_or(Malformed)?;
    let body = bytes.get(at..end).ok_or(Malformed)?;
    Ok((
        Item {
            list,
            payload: body,
            whole: &bytes[..end],
        },
        &bytes[end..],
    ))
}

/// The items of the one list `bytes` is, with nothing before or after it.
pub fn list_items(bytes: &[u8]) -> Result<Vec<Item<'_>>, Malformed> {
    let (head, rest) = split(bytes)?;
    if !rest.is_empty() {
        return Err(Malformed);
    }
    items(&head)
}

/// The items of a list item.
pub fn items<'a>(item: &Item<'a>) -> Result<Vec<Item<'a>>, Malformed> {
    if !item.list {
        return Err(Malformed);
    }
    let mut out = Vec::new();
    let mut at = item.payload;
    while !at.is_empty() {
        let (next, rest) = split(at)?;
        out.push(next);
        at = rest;
    }
    Ok(out)
}

/// A byte string's bytes.
pub fn bytes<'a>(item: &Item<'a>) -> Result<&'a [u8], Malformed> {
    if item.list {
        return Err(Malformed);
    }
    Ok(item.payload)
}

/// An exactly-`N`-byte string.
pub fn fixed<const N: usize>(item: &Item<'_>) -> Result<[u8; N], Malformed> {
    bytes(item)?.try_into().map_err(|_| Malformed)
}

/// A canonical big-endian integer of at most `width` bytes: no leading zero,
/// zero as the empty string.
fn uint<'a>(item: &Item<'a>, width: usize) -> Result<&'a [u8], Malformed> {
    let be = bytes(item)?;
    if be.len() > width || be.first() == Some(&0) {
        return Err(Malformed);
    }
    Ok(be)
}

/// A canonical integer that fits a `u64`.
pub fn u64_of(item: &Item<'_>) -> Result<u64, Malformed> {
    Ok(uint(item, 8)?
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | *byte as u64))
}

/// A canonical integer that fits a `u128`.
pub fn u128_of(item: &Item<'_>) -> Result<u128, Malformed> {
    Ok(uint(item, 16)?
        .iter()
        .fold(0u128, |acc, byte| (acc << 8) | *byte as u128))
}

/// A canonical integer below `2^256`, as a big-endian word.
pub fn word_of(item: &Item<'_>) -> Result<Word32, Malformed> {
    let be = uint(item, 32)?;
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(be);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Append the RLP of a byte string.
pub fn encode_bytes(out: &mut Vec<u8>, payload: &[u8]) {
    if payload.len() == 1 && payload[0] < 0x80 {
        out.push(payload[0]);
        return;
    }
    encode_header(out, payload.len(), 0x80);
    out.extend_from_slice(payload);
}

/// Append the RLP of a list whose payload — the concatenation of its items'
/// complete encodings — is already built.
pub fn encode_list(out: &mut Vec<u8>, payload: &[u8]) {
    encode_header(out, payload.len(), 0xc0);
    out.extend_from_slice(payload);
}

/// Append the RLP of a non-negative integer given big-endian: **minimal**, with
/// zero as the empty string.
pub fn encode_uint(out: &mut Vec<u8>, be: &[u8]) {
    let start = be.iter().position(|b| *b != 0).unwrap_or(be.len());
    encode_bytes(out, &be[start..]);
}

/// Append the RLP of a `u64`.
pub fn encode_u64(out: &mut Vec<u8>, value: u64) {
    encode_uint(out, &value.to_be_bytes());
}

/// Append a string or list header for a payload of `len` bytes.
pub fn encode_header(out: &mut Vec<u8>, len: usize, short: u8) {
    if len <= 55 {
        out.push(short + len as u8);
        return;
    }
    let be = (len as u64).to_be_bytes();
    let start = be
        .iter()
        .position(|b| *b != 0)
        .expect("len > 55 is nonzero");
    out.push(short + 55 + (8 - start) as u8);
    out.extend_from_slice(&be[start..]);
}

/// How many bytes a string or list header for a `len`-byte payload takes.
pub fn header_len(len: usize) -> usize {
    if len <= 55 {
        1
    } else {
        1 + (usize::BITS - len.leading_zeros()).div_ceil(8) as usize
    }
}
