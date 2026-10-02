//! The canonical stateless input and output, as `ethereum/execution-specs`
//! writes them at `tests-zkevm@v21.0.1` (`forks/amsterdam/stateless.py`):
//! `statelessInputBytes` in, the 43-byte `statelessOutputBytes` out.
//!
//! ```text
//!   input   schema_id (2 bytes, big-endian) ‖ SSZ(StatelessInput)
//!   output  SSZ(StatelessValidationResult)
//!             new_payload_request_root  32
//!             successful_validation      1
//!             chain_id                   8   little-endian
//!             schema_id                  2   little-endian
//! ```
//!
//! **The decoder is exactly as strict as the spec's.** `v21.0.1` made every
//! SSZ mutation in its fixtures break decoding, and an input that does not
//! decode publishes the all-zero sentinel rather than `false` — so a decoder
//! that accepted one the spec refuses would publish a different 43 bytes. Every
//! offset is checked against the bytes it bounds, every bounded list against
//! its limit, and nothing may follow the last field.
//!
//! The schema id names the fork, and the request's layout follows it: Osaka,
//! BPO1 and BPO2 (`0x1201`–`0x1401`) share the Electra/Fulu request, Amsterdam
//! (`0x1501`) the Gloas one, which adds a block access list, a slot number and
//! the two EIP-8282 builder request lists. Everything is borrowed from the
//! input: on the guest that is the advice region, and no transaction, node or
//! code is copied out of it to be decoded.

use alloc::vec::Vec;

use crate::block::{self, Fork, Withdrawal};
use crate::{Address20, Word32};

/// Bytes that are not a canonical stateless input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Malformed;

/// Every list bound the schema states. Progressive lists have none.
const MAX_EXTRA_DATA_BYTES: usize = 32;
const MAX_WITNESS_HEADERS: usize = 256;
const MAX_BYTES_PER_WITNESS_NODE: usize = 1 << 10;
const MAX_BYTES_PER_CODE: usize = 1 << 16;
const MAX_BYTES_PER_HEADER: usize = 1 << 10;

/// The byte size of each request type's SSZ item, by type byte: deposits,
/// withdrawal requests, consolidations, builder deposits, builder exits.
pub const REQUEST_ITEM_BYTES: [usize; 5] = [192, 76, 116, 184, 68];

/// A decoded stateless input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatelessInput<'a> {
    pub fork: Fork,
    pub request: NewPayloadRequest<'a>,
    pub witness: ExecutionWitness<'a>,
    pub chain_id: u64,
    /// One uncompressed public key per transaction, in ere-guests' layout
    /// only: `tests-zkevm@v21.0.1` dropped the field.
    pub public_keys: Option<Vec<&'a [u8; 65]>>,
}

/// The consensus layer's `NewPayloadRequest`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewPayloadRequest<'a> {
    pub payload: ExecutionPayload<'a>,
    pub versioned_hashes: Vec<Word32>,
    pub parent_beacon_block_root: Word32,
    /// Each request type's list, as its items' concatenated SSZ, by type byte.
    /// Types 3 and 4 are Amsterdam's and empty before it.
    pub requests: [&'a [u8]; 5],
}

/// The execution payload: Electra/Fulu's, or Gloas' with the last two fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionPayload<'a> {
    pub parent_hash: Word32,
    pub fee_recipient: Address20,
    pub state_root: Word32,
    pub receipts_root: Word32,
    pub logs_bloom: [u8; 256],
    pub prev_randao: Word32,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: &'a [u8],
    /// A `uint256`, little-endian as SSZ stores it.
    pub base_fee_per_gas: Word32,
    pub block_hash: Word32,
    pub transactions: Vec<&'a [u8]>,
    pub withdrawals: Vec<Withdrawal>,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
    /// Gloas: the block access list's RLP.
    pub block_access_list: Option<&'a [u8]>,
    /// Gloas: the slot number.
    pub slot_number: Option<u64>,
}

/// The witness: trie-node preimages, code preimages and ancestor headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionWitness<'a> {
    pub state: Vec<&'a [u8]>,
    pub codes: Vec<&'a [u8]>,
    /// RLP headers, oldest first, the parent last.
    pub headers: Vec<&'a [u8]>,
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// A field of a container: fixed-size bytes, or a variable part's offset.
enum Field {
    Fixed(usize),
    Variable,
}

/// A container's fields, each its bytes, strictly: the fixed part read in
/// order, every variable field's offset in range and in order, the first one
/// exactly where the fixed part ends, and the last field running to the end.
fn container<'a>(bytes: &'a [u8], fields: &[Field]) -> Result<Vec<&'a [u8]>, Malformed> {
    let fixed_len: usize = fields
        .iter()
        .map(|f| match f {
            Field::Fixed(n) => *n,
            Field::Variable => 4,
        })
        .sum();
    if bytes.len() < fixed_len {
        return Err(Malformed);
    }
    let mut out = Vec::with_capacity(fields.len());
    let mut offsets = Vec::new();
    let mut at = 0;
    for field in fields {
        match field {
            Field::Fixed(n) => {
                out.push(&bytes[at..at + n]);
                at += n;
            }
            Field::Variable => {
                offsets.push((out.len(), u32_at(bytes, at) as usize));
                out.push(&[][..]);
                at += 4;
            }
        }
    }
    if let Some((_, first)) = offsets.first() {
        if *first != fixed_len {
            return Err(Malformed);
        }
    } else if bytes.len() != fixed_len {
        return Err(Malformed);
    }
    for (i, (index, start)) in offsets.iter().enumerate() {
        let end = offsets.get(i + 1).map_or(bytes.len(), |(_, next)| *next);
        if *start > end || end > bytes.len() {
            return Err(Malformed);
        }
        out[*index] = &bytes[*start..end];
    }
    Ok(out)
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
}

fn u64_of(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("eight bytes"))
}

fn word_of(bytes: &[u8]) -> Word32 {
    bytes.try_into().expect("thirty-two bytes")
}

/// A list of variable-size elements: an offset per element, then the
/// elements. Empty is zero bytes. `limit` bounds the count, when the list has
/// one.
fn variable_list(bytes: &[u8], limit: Option<usize>) -> Result<Vec<&[u8]>, Malformed> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() < 4 {
        return Err(Malformed);
    }
    let first = u32_at(bytes, 0) as usize;
    if !first.is_multiple_of(4) || first == 0 || first > bytes.len() {
        return Err(Malformed);
    }
    let count = first / 4;
    if limit.is_some_and(|limit| count > limit) {
        return Err(Malformed);
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let start = u32_at(bytes, 4 * i) as usize;
        let end = if i + 1 < count {
            u32_at(bytes, 4 * (i + 1)) as usize
        } else {
            bytes.len()
        };
        if start > end || end > bytes.len() {
            return Err(Malformed);
        }
        out.push(&bytes[start..end]);
    }
    Ok(out)
}

/// A list of `size`-byte elements.
fn fixed_list(bytes: &[u8], size: usize) -> Result<Vec<&[u8]>, Malformed> {
    if !bytes.len().is_multiple_of(size) {
        return Err(Malformed);
    }
    Ok(bytes.chunks_exact(size).collect())
}

/// Every element at most `max` bytes: a bounded byte list's limit.
fn bounded(items: Vec<&[u8]>, max: usize) -> Result<Vec<&[u8]>, Malformed> {
    if items.iter().any(|item| item.len() > max) {
        return Err(Malformed);
    }
    Ok(items)
}

/// `schema_id ‖ SSZ(StatelessInput)`, strictly, in either of its two layouts:
/// `tests-zkevm@v21.0.1`'s request, witness and chain id, or ere-guests'
/// v0.17.1 — what the zkEVM benchmark's datasets carry — with `public_keys`
/// after them. A container's first offset is its fixed size, 16 or 20, so no
/// input is both. `None` is the spec's "could not decode", which publishes the
/// all-zero sentinel: bytes too short for a schema id, a schema id this guest
/// does not validate, or an SSZ body that is exactly neither layout of that
/// fork.
pub fn decode(bytes: &[u8]) -> Option<StatelessInput<'_>> {
    use Field::{Fixed, Variable};
    let (schema, body) = bytes.split_first_chunk::<2>()?;
    let fork = block::fork(u16::from_be_bytes(*schema))?;
    let input = (|| -> Result<StatelessInput<'_>, Malformed> {
        let top = container(body, &[Variable, Variable, Fixed(8)])
            .or_else(|_| container(body, &[Variable, Variable, Fixed(8), Variable]))?;
        let public_keys = top.get(3).map(|keys| fixed_list(keys, 65)).transpose()?;
        Ok(StatelessInput {
            fork,
            request: request(top[0], fork.amsterdam)?,
            witness: witness(top[1])?,
            chain_id: u64_of(top[2]),
            public_keys: public_keys.map(|keys| {
                keys.into_iter()
                    .map(|key| key.try_into().expect("sixty-five bytes"))
                    .collect()
            }),
        })
    })();
    input.ok()
}

fn request(bytes: &[u8], amsterdam: bool) -> Result<NewPayloadRequest<'_>, Malformed> {
    let f = container(
        bytes,
        &[
            Field::Variable,
            Field::Variable,
            Field::Fixed(32),
            Field::Variable,
        ],
    )?;
    let types = if amsterdam { 5 } else { 3 };
    let lists = container(
        f[3],
        &(0..types).map(|_| Field::Variable).collect::<Vec<_>>(),
    )?;
    let mut requests: [&[u8]; 5] = [&[]; 5];
    for (i, list) in lists.iter().enumerate() {
        fixed_list(list, REQUEST_ITEM_BYTES[i])?;
        requests[i] = list;
    }
    Ok(NewPayloadRequest {
        payload: payload(f[0], amsterdam)?,
        versioned_hashes: fixed_list(f[1], 32)?.into_iter().map(word_of).collect(),
        parent_beacon_block_root: word_of(f[2]),
        requests,
    })
}

fn payload(bytes: &[u8], amsterdam: bool) -> Result<ExecutionPayload<'_>, Malformed> {
    use Field::{Fixed, Variable};
    let mut layout = Vec::from([
        Fixed(32),  // parent_hash
        Fixed(20),  // fee_recipient
        Fixed(32),  // state_root
        Fixed(32),  // receipts_root
        Fixed(256), // logs_bloom
        Fixed(32),  // prev_randao
        Fixed(8),   // block_number
        Fixed(8),   // gas_limit
        Fixed(8),   // gas_used
        Fixed(8),   // timestamp
        Variable,   // extra_data
        Fixed(32),  // base_fee_per_gas
        Fixed(32),  // block_hash
        Variable,   // transactions
        Variable,   // withdrawals
        Fixed(8),   // blob_gas_used
        Fixed(8),   // excess_blob_gas
    ]);
    if amsterdam {
        layout.push(Variable); // block_access_list
        layout.push(Fixed(8)); // slot_number
    }
    let f = container(bytes, &layout)?;
    if f[10].len() > MAX_EXTRA_DATA_BYTES {
        return Err(Malformed);
    }
    let withdrawals = fixed_list(f[14], 44)?
        .into_iter()
        .map(|w| Withdrawal {
            index: u64_of(&w[0..8]),
            validator_index: u64_of(&w[8..16]),
            address: w[16..36].try_into().expect("twenty bytes"),
            amount: u64_of(&w[36..44]),
        })
        .collect();
    Ok(ExecutionPayload {
        parent_hash: word_of(f[0]),
        fee_recipient: f[1].try_into().expect("twenty bytes"),
        state_root: word_of(f[2]),
        receipts_root: word_of(f[3]),
        logs_bloom: f[4].try_into().expect("256 bytes"),
        prev_randao: word_of(f[5]),
        block_number: u64_of(f[6]),
        gas_limit: u64_of(f[7]),
        gas_used: u64_of(f[8]),
        timestamp: u64_of(f[9]),
        extra_data: f[10],
        base_fee_per_gas: word_of(f[11]),
        block_hash: word_of(f[12]),
        transactions: variable_list(f[13], None)?,
        withdrawals,
        blob_gas_used: u64_of(f[15]),
        excess_blob_gas: u64_of(f[16]),
        block_access_list: amsterdam.then(|| f[17]),
        slot_number: amsterdam.then(|| u64_of(f[18])),
    })
}

fn witness(bytes: &[u8]) -> Result<ExecutionWitness<'_>, Malformed> {
    let f = container(bytes, &[Field::Variable, Field::Variable, Field::Variable])?;
    Ok(ExecutionWitness {
        state: bounded(variable_list(f[0], None)?, MAX_BYTES_PER_WITNESS_NODE)?,
        codes: bounded(variable_list(f[1], None)?, MAX_BYTES_PER_CODE)?,
        headers: bounded(
            variable_list(f[2], Some(MAX_WITNESS_HEADERS))?,
            MAX_BYTES_PER_HEADER,
        )?,
    })
}

// ---------------------------------------------------------------------------
// hash_tree_root
// ---------------------------------------------------------------------------
//
// SSZ's merkleization with SHA-256, as `eth-remerkleable` 0.1.31 computes it —
// the version `tests-zkevm@v21.0.1` locks. The progressive forms are
// EIP-7916's and EIP-7495's **as of 2026-01-15**, when EIP-7916 moved the
// recursion to the right: an implementation from before that date roots every
// progressive list differently. Only the shapes this schema uses are here.

/// `H(a, b)`: SHA-256 over two chunks, `a` the left child.
fn h(a: &Word32, b: &Word32) -> Word32 {
    let mut pair = [0u8; 64];
    pair[..32].copy_from_slice(a);
    pair[32..].copy_from_slice(b);
    crate::sha256(&pair)
}

/// Bytes as 32-byte chunks, the last zero-padded; nothing is no chunks.
fn pack(bytes: &[u8]) -> Vec<Word32> {
    bytes
        .chunks(32)
        .map(|c| {
            let mut chunk = [0u8; 32];
            chunk[..c.len()].copy_from_slice(c);
            chunk
        })
        .collect()
}

/// A little-endian integer's chunk.
fn chunk_of(le: &[u8]) -> Word32 {
    let mut chunk = [0u8; 32];
    chunk[..le.len()].copy_from_slice(le);
    chunk
}

/// The full binary tree over `chunks`, `width` leaves wide (a power of two),
/// the missing leaves zero. The zero subtree is hashed up beside the data
/// rather than read from a table: a progressive list's subtrees are `4^k`
/// leaves wide with no bound but the input's size, and a table sized by an
/// argument about that bound is what once rooted a 400 kB transaction wrong.
fn merkleize(chunks: &[Word32], width: usize) -> Word32 {
    let mut layer = chunks.to_vec();
    let mut zero = [0u8; 32];
    for _ in 0..width.trailing_zeros() {
        if layer.len() % 2 == 1 {
            layer.push(zero);
        }
        layer = layer.chunks_exact(2).map(|p| h(&p[0], &p[1])).collect();
        zero = h(&zero, &zero);
    }
    layer.first().copied().unwrap_or(zero)
}

/// EIP-7916's progressive tree: `H(full tree of the first num_leaves, the rest
/// progressively at four times the width)`, ending in a zero chunk.
fn merkleize_progressive(chunks: &[Word32], num_leaves: usize) -> Word32 {
    if chunks.is_empty() {
        return [0u8; 32];
    }
    let split = num_leaves.min(chunks.len());
    let left = merkleize(&chunks[..split], num_leaves);
    let right = merkleize_progressive(&chunks[split..], 4 * num_leaves);
    h(&left, &right)
}

fn mix_in_length(root: &Word32, len: usize) -> Word32 {
    h(root, &chunk_of(&(len as u64).to_le_bytes()))
}

/// EIP-7495: a progressive container's root, every one of its `fields` active.
fn progressive_container(fields: &[Word32]) -> Word32 {
    let mut active = [0u8; 32];
    for i in 0..fields.len() {
        active[i / 8] |= 1 << (i % 8);
    }
    h(&merkleize_progressive(fields, 1), &active)
}

/// A `ProgressiveByteList` (and a `ProgressiveList` of a basic type).
fn progressive_bytes(bytes: &[u8]) -> Word32 {
    mix_in_length(&merkleize_progressive(&pack(bytes), 1), bytes.len())
}

/// A `ByteVector[N]` of more than 32 bytes: a Bytes48 pubkey, a Bytes96
/// signature, the Bytes256 bloom.
fn vector(bytes: &[u8]) -> Word32 {
    merkleize(&pack(bytes), bytes.len().div_ceil(32).next_power_of_two())
}

/// One request item's root, from its SSZ bytes, by request type.
fn request_item(kind: usize, item: &[u8]) -> Word32 {
    let fields = match kind {
        // DepositRequest: pubkey, withdrawal_credentials, amount, signature, index.
        0 => Vec::from([
            vector(&item[0..48]),
            word_of(&item[48..80]),
            chunk_of(&item[80..88]),
            vector(&item[88..184]),
            chunk_of(&item[184..192]),
        ]),
        // WithdrawalRequest: source_address, validator_pubkey, amount.
        1 => Vec::from([
            chunk_of(&item[0..20]),
            vector(&item[20..68]),
            chunk_of(&item[68..76]),
        ]),
        // ConsolidationRequest: source_address, source_pubkey, target_pubkey.
        2 => Vec::from([
            chunk_of(&item[0..20]),
            vector(&item[20..68]),
            vector(&item[68..116]),
        ]),
        // BuilderDepositRequest: pubkey, withdrawal_credentials, amount, signature.
        3 => Vec::from([
            vector(&item[0..48]),
            word_of(&item[48..80]),
            chunk_of(&item[80..88]),
            vector(&item[88..184]),
        ]),
        // BuilderExitRequest: source_address, pubkey.
        _ => Vec::from([chunk_of(&item[0..20]), vector(&item[20..68])]),
    };
    merkleize(&fields, fields.len().next_power_of_two())
}

/// `hash_tree_root(NewPayloadRequest)`: the `new_payload_request_root` the
/// result publishes.
pub fn request_root(request: &NewPayloadRequest<'_>, amsterdam: bool) -> Word32 {
    let p = &request.payload;
    let transactions: Vec<Word32> = p
        .transactions
        .iter()
        .map(|tx| progressive_bytes(tx))
        .collect();
    let withdrawals: Vec<Word32> = p
        .withdrawals
        .iter()
        .map(|w| {
            let fields = [
                chunk_of(&w.index.to_le_bytes()),
                chunk_of(&w.validator_index.to_le_bytes()),
                chunk_of(&w.address),
                chunk_of(&w.amount.to_le_bytes()),
            ];
            merkleize(&fields, 4)
        })
        .collect();
    let mut fields = Vec::from([
        p.parent_hash,
        chunk_of(&p.fee_recipient),
        p.state_root,
        p.receipts_root,
        vector(&p.logs_bloom),
        p.prev_randao,
        chunk_of(&p.block_number.to_le_bytes()),
        chunk_of(&p.gas_limit.to_le_bytes()),
        chunk_of(&p.gas_used.to_le_bytes()),
        chunk_of(&p.timestamp.to_le_bytes()),
        // `ByteList[32]`: one chunk wide.
        mix_in_length(&merkleize(&pack(p.extra_data), 1), p.extra_data.len()),
        p.base_fee_per_gas,
        p.block_hash,
        mix_in_length(&merkleize_progressive(&transactions, 1), transactions.len()),
        mix_in_length(&merkleize_progressive(&withdrawals, 1), withdrawals.len()),
        chunk_of(&p.blob_gas_used.to_le_bytes()),
        chunk_of(&p.excess_blob_gas.to_le_bytes()),
    ]);
    if amsterdam {
        fields.push(progressive_bytes(p.block_access_list.unwrap_or(&[])));
        fields.push(chunk_of(&p.slot_number.unwrap_or(0).to_le_bytes()));
    }
    let payload = progressive_container(&fields);

    let versioned_hashes = mix_in_length(
        &merkleize_progressive(&request.versioned_hashes, 1),
        request.versioned_hashes.len(),
    );

    let types = if amsterdam { 5 } else { 3 };
    let lists: Vec<Word32> = (0..types)
        .map(|kind| {
            let items: Vec<Word32> = request.requests[kind]
                .chunks_exact(REQUEST_ITEM_BYTES[kind])
                .map(|item| request_item(kind, item))
                .collect();
            mix_in_length(&merkleize_progressive(&items, 1), items.len())
        })
        .collect();
    let requests = progressive_container(&lists);

    merkleize(
        &[
            payload,
            versioned_hashes,
            request.parent_beacon_block_root,
            requests,
        ],
        4,
    )
}

// ---------------------------------------------------------------------------
// The result
// ---------------------------------------------------------------------------

/// `SSZ(StatelessValidationResult)`: the request's root, the verdict, the
/// chain id and the schema id.
pub fn result(request_root: &Word32, valid: bool, chain_id: u64, schema_id: u16) -> [u8; 43] {
    let mut out = [0u8; 43];
    out[..32].copy_from_slice(request_root);
    out[32] = valid as u8;
    out[33..41].copy_from_slice(&chain_id.to_le_bytes());
    out[41..].copy_from_slice(&schema_id.to_le_bytes());
    out
}

/// The output when the input cannot be decoded or its schema is not one this
/// guest validates: every field zero.
pub const SENTINEL: [u8; 43] = [0u8; 43];
