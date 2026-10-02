//! A block's header, the forks this guest validates, and what the chain derives
//! from a block's contents: the ordered tries, the receipts and their bloom,
//! the withdrawals' encoding, the requests hash, and the rules a header obeys
//! against its parent.
//!
//! The reference for every rule here is `ethereum/execution-specs` at
//! `tests-zkevm@v21.0.1`: `forks/osaka/` for the three Osaka-family forks and
//! `forks/amsterdam/` for Amsterdam — `blocks.py`, `bloom.py`, `requests.py`,
//! `fork.py::validate_header` and `vm/gas.py::calculate_excess_blob_gas`.

use alloc::vec::Vec;

use revm::primitives::hardfork::SpecId;

use crate::rlp::{self, Malformed};
use crate::{keccak, mpt, Address20, Word32};

// ---------------------------------------------------------------------------
// Forks
// ---------------------------------------------------------------------------

/// Gas per blob, EIP-4844.
pub const GAS_PER_BLOB: u64 = 1 << 17;

/// EIP-7918's reserve price: a blob's execution-gas floor.
const BLOB_BASE_COST: u128 = 1 << 13;

/// EIP-7594's per-transaction blob cap, in Osaka and Amsterdam alike.
pub const MAX_BLOBS_PER_TX: u64 = 6;

/// EIP-7934's ceiling on a block's RLP size: 10 MiB less a 2 MiB margin.
pub const MAX_RLP_BLOCK_SIZE: usize = 10_485_760 - 2_097_152;

/// `keccak256(rlp([]))`, which every post-merge header's ommers hash is.
pub const EMPTY_OMMER_HASH: Word32 = [
    0x1d, 0xcc, 0x4d, 0xe8, 0xde, 0xc7, 0x5d, 0x7a, 0xab, 0x85, 0xb5, 0x67, 0xb6, 0xcc, 0xd4, 0x1a,
    0xd3, 0x12, 0x45, 0x1b, 0x94, 0x8a, 0x74, 0x13, 0xf0, 0xa1, 0x42, 0xfd, 0x40, 0xd4, 0x93, 0x47,
];

/// One fork this guest validates, named by its stateless schema id.
///
/// The schema id is `fork_index << 8 | 0x01`, with `fork_index` from the
/// spec's `ProtocolFork` (`forks/amsterdam/stateless.py`): the spec defines the
/// schema for Amsterdam alone, and the benchmark crate (`eth-act/ere-guests`'
/// `stateless-validator-common`) extends the same identifier to every earlier
/// fork. **The fork comes from the schema id and from nothing else** — no
/// activation timestamp is compiled in — exactly as the spec's own guest does,
/// and the schema id is published beside the result so a verifier sees whose
/// rules were applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fork {
    /// `fork_index << 8 | revision`.
    pub schema_id: u16,
    /// The revm rules the block executes under.
    pub spec: SpecId,
    /// Amsterdam's header and payload carry a block access list hash and a
    /// slot number, and its requests carry builder deposits and exits.
    pub amsterdam: bool,
    /// The blob schedule (EIP-7840): target and max blobs per block, and the
    /// base-fee update fraction.
    pub blob_target: u64,
    pub blob_max: u64,
    pub blob_fraction: u64,
}

/// The forks a schema id may name here, from `forks/{osaka,bpo1,bpo2,
/// amsterdam}/vm/gas.py`'s blob schedules. Everything else — earlier forks,
/// later ones, another revision — is a schema this guest cannot validate.
pub fn fork(schema_id: u16) -> Option<Fork> {
    let (spec, amsterdam, blob_target, blob_max, blob_fraction) = match schema_id {
        // Osaka.
        0x1201 => (SpecId::OSAKA, false, 6, 9, 5_007_716),
        // BPO1 and BPO2 change the blob schedule and nothing else.
        0x1301 => (SpecId::OSAKA, false, 10, 15, 8_346_193),
        0x1401 => (SpecId::OSAKA, false, 14, 21, 11_684_671),
        0x1501 => (SpecId::AMSTERDAM, true, 14, 21, 11_684_671),
        _ => return None,
    };
    Some(Fork {
        schema_id,
        spec,
        amsterdam,
        blob_target,
        blob_max,
        blob_fraction,
    })
}

/// EIP-4844's `fake_exponential`, with every step checked: `None` when the
/// result does not fit a `u128`.
///
/// revm's own is unchecked `u128` arithmetic, and the guest builds with
/// overflow checks on — so a parent header with a large enough
/// `excess_blob_gas` would *panic* it, and a guest that panics publishes no
/// result at all. A price at or above `2^128` wei a gas is no price any
/// transaction can pay; the callers say what that means.
pub fn fake_exponential(factor: u128, numerator: u128, denominator: u128) -> Option<u128> {
    let mut i: u128 = 1;
    let mut output: u128 = 0;
    let mut accumulator = factor.checked_mul(denominator)?;
    while accumulator > 0 {
        output = output.checked_add(accumulator)?;
        accumulator = accumulator.checked_mul(numerator)? / denominator.checked_mul(i)?;
        i += 1;
    }
    Some(output / denominator)
}

/// The blob gas price an `excess_blob_gas` implies under `fork`, or `None` past
/// `2^128`.
pub fn blob_gas_price(fork: &Fork, excess_blob_gas: u64) -> Option<u128> {
    fake_exponential(1, excess_blob_gas as u128, fork.blob_fraction as u128)
}

// ---------------------------------------------------------------------------
// The header
// ---------------------------------------------------------------------------

/// A post-merge header: Osaka's 21 fields, or Amsterdam's 23.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub parent_hash: Word32,
    pub ommers_hash: Word32,
    pub coinbase: Address20,
    pub state_root: Word32,
    pub transactions_root: Word32,
    pub receipts_root: Word32,
    pub bloom: [u8; 256],
    /// Zero after the merge; a `Uint` in the spec.
    pub difficulty: Word32,
    pub number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub prev_randao: Word32,
    pub nonce: [u8; 8],
    pub base_fee_per_gas: u64,
    pub withdrawals_root: Word32,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
    pub parent_beacon_block_root: Word32,
    pub requests_hash: Word32,
    /// EIP-7928, from Amsterdam: `keccak256` of the block access list's RLP.
    pub block_access_list_hash: Option<Word32>,
    /// EIP-7843, from Amsterdam.
    pub slot_number: Option<u64>,
}

impl Header {
    /// The header's RLP.
    ///
    /// Panics on a header carrying exactly one of the two Amsterdam fields:
    /// they are one fork's, so a header with one is a broken caller.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(700);
        rlp::encode_bytes(&mut out, &self.parent_hash);
        rlp::encode_bytes(&mut out, &self.ommers_hash);
        rlp::encode_bytes(&mut out, &self.coinbase);
        rlp::encode_bytes(&mut out, &self.state_root);
        rlp::encode_bytes(&mut out, &self.transactions_root);
        rlp::encode_bytes(&mut out, &self.receipts_root);
        rlp::encode_bytes(&mut out, &self.bloom);
        rlp::encode_uint(&mut out, &self.difficulty);
        rlp::encode_u64(&mut out, self.number);
        rlp::encode_u64(&mut out, self.gas_limit);
        rlp::encode_u64(&mut out, self.gas_used);
        rlp::encode_u64(&mut out, self.timestamp);
        rlp::encode_bytes(&mut out, &self.extra_data);
        rlp::encode_bytes(&mut out, &self.prev_randao);
        rlp::encode_bytes(&mut out, &self.nonce);
        rlp::encode_u64(&mut out, self.base_fee_per_gas);
        rlp::encode_bytes(&mut out, &self.withdrawals_root);
        rlp::encode_u64(&mut out, self.blob_gas_used);
        rlp::encode_u64(&mut out, self.excess_blob_gas);
        rlp::encode_bytes(&mut out, &self.parent_beacon_block_root);
        rlp::encode_bytes(&mut out, &self.requests_hash);
        match (self.block_access_list_hash, self.slot_number) {
            (Some(hash), Some(slot)) => {
                rlp::encode_bytes(&mut out, &hash);
                rlp::encode_u64(&mut out, slot);
            }
            (None, None) => {}
            _ => panic!("a header carries both Amsterdam fields or neither"),
        }
        let mut header = Vec::with_capacity(out.len() + 3);
        rlp::encode_list(&mut header, &out);
        header
    }

    /// The block hash.
    pub fn hash(&self) -> Word32 {
        keccak(&self.encode())
    }

    /// A header from its RLP, strictly: 21 fields, or 23 when `amsterdam`
    /// allows Amsterdam's two.
    ///
    /// The integers the spec types `Uint` or `U256` — number, gas limit, gas
    /// used, timestamp, base fee — are taken as `u64`, which is what revm can
    /// execute and what every real header holds; a header past that is refused,
    /// which is the verdict a block built on it reaches anyway.
    pub fn decode(bytes: &[u8], amsterdam: bool) -> Result<Header, Malformed> {
        let items = rlp::list_items(bytes)?;
        let (block_access_list_hash, slot_number) = match items.len() {
            21 => (None, None),
            23 if amsterdam => (
                Some(rlp::fixed::<32>(&items[21])?),
                Some(rlp::u64_of(&items[22])?),
            ),
            _ => return Err(Malformed),
        };
        Ok(Header {
            parent_hash: rlp::fixed::<32>(&items[0])?,
            ommers_hash: rlp::fixed::<32>(&items[1])?,
            coinbase: rlp::fixed::<20>(&items[2])?,
            state_root: rlp::fixed::<32>(&items[3])?,
            transactions_root: rlp::fixed::<32>(&items[4])?,
            receipts_root: rlp::fixed::<32>(&items[5])?,
            bloom: rlp::fixed::<256>(&items[6])?,
            difficulty: rlp::word_of(&items[7])?,
            number: rlp::u64_of(&items[8])?,
            gas_limit: rlp::u64_of(&items[9])?,
            gas_used: rlp::u64_of(&items[10])?,
            timestamp: rlp::u64_of(&items[11])?,
            extra_data: rlp::bytes(&items[12])?.to_vec(),
            prev_randao: rlp::fixed::<32>(&items[13])?,
            nonce: rlp::fixed::<8>(&items[14])?,
            base_fee_per_gas: rlp::u64_of(&items[15])?,
            withdrawals_root: rlp::fixed::<32>(&items[16])?,
            blob_gas_used: rlp::u64_of(&items[17])?,
            excess_blob_gas: rlp::u64_of(&items[18])?,
            parent_beacon_block_root: rlp::fixed::<32>(&items[19])?,
            requests_hash: rlp::fixed::<32>(&items[20])?,
            block_access_list_hash,
            slot_number,
        })
    }
}

/// Every way a header fails against its parent. One variant per rule, in
/// `validate_header`'s order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderError {
    NumberZero,
    ExcessBlobGas,
    GasUsedOverLimit,
    GasLimit,
    BaseFee,
    Timestamp,
    Number,
    ExtraData,
    Difficulty,
    Nonce,
    OmmersHash,
    ParentHash,
}

/// `fork.py::validate_header`: the header against its parent, rule by rule.
///
/// `parent_hash` is `keccak256` of the parent's bytes as the witness carried
/// them, which the strict decoder has already held to their one encoding.
pub fn validate_header(
    fork: &Fork,
    parent: &Header,
    parent_hash: &Word32,
    header: &Header,
) -> Result<(), HeaderError> {
    if header.number < 1 {
        return Err(HeaderError::NumberZero);
    }
    if Some(header.excess_blob_gas) != excess_blob_gas(fork, parent) {
        return Err(HeaderError::ExcessBlobGas);
    }
    if header.gas_used > header.gas_limit {
        return Err(HeaderError::GasUsedOverLimit);
    }
    if !gas_limit_fits(header.gas_limit, parent.gas_limit) {
        return Err(HeaderError::GasLimit);
    }
    if header.base_fee_per_gas != base_fee(parent) {
        return Err(HeaderError::BaseFee);
    }
    if header.timestamp <= parent.timestamp {
        return Err(HeaderError::Timestamp);
    }
    if Some(header.number) != parent.number.checked_add(1) {
        return Err(HeaderError::Number);
    }
    if header.extra_data.len() > 32 {
        return Err(HeaderError::ExtraData);
    }
    if header.difficulty != [0u8; 32] {
        return Err(HeaderError::Difficulty);
    }
    if header.nonce != [0u8; 8] {
        return Err(HeaderError::Nonce);
    }
    if header.ommers_hash != EMPTY_OMMER_HASH {
        return Err(HeaderError::OmmersHash);
    }
    if header.parent_hash != *parent_hash {
        return Err(HeaderError::ParentHash);
    }
    Ok(())
}

/// `check_gas_limit`: within a 1/1024 step of the parent's, and at least 5000.
fn gas_limit_fits(gas_limit: u64, parent_gas_limit: u64) -> bool {
    let delta = parent_gas_limit / 1024;
    gas_limit < parent_gas_limit.saturating_add(delta)
        && gas_limit > parent_gas_limit - delta
        && gas_limit >= 5000
}

/// EIP-1559's base fee for the child of `parent`.
///
/// `u128` throughout: a base fee and a gas difference are each below `2^64`,
/// so their product cannot overflow, and the result is never above the
/// parent's base fee plus that product over a positive divisor.
pub fn base_fee(parent: &Header) -> u64 {
    let base = parent.base_fee_per_gas as u128;
    let used = parent.gas_used as u128;
    let target = (parent.gas_limit / 2) as u128;
    if target == 0 || used == target {
        return parent.base_fee_per_gas;
    }
    let fee = if used > target {
        let delta = core::cmp::max(base * (used - target) / target / 8, 1);
        base + delta
    } else {
        base - base * (target - used) / target / 8
    };
    // Above `u64::MAX` only past a base fee no real header holds; saturating
    // keeps the comparison it feeds a mismatch rather than a panic.
    u64::try_from(fee).unwrap_or(u64::MAX)
}

/// EIP-4844's excess blob gas for the child of `parent`, with EIP-7918's
/// reserve price, under `fork`'s schedule — the child's, which is the rule at a
/// fork boundary. `None` when the parent's excess and blob gas overflow a
/// `u64`, which the spec's `U64` addition refuses too.
pub fn excess_blob_gas(fork: &Fork, parent: &Header) -> Option<u64> {
    let target = fork.blob_target * GAS_PER_BLOB;
    let parent_blob_gas = parent.excess_blob_gas.checked_add(parent.blob_gas_used)?;
    if parent_blob_gas < target {
        return Some(0);
    }
    // EIP-7918: when a blob's execution-gas floor outprices its blob gas, the
    // excess grows by the blobs above target instead of falling. A target
    // price past `2^128` outprices any floor (`2^13` times a `u64` base fee
    // is below `2^77`), so an overflow is that comparison's answer and not an
    // error.
    let reserve_binds = blob_gas_price(fork, parent.excess_blob_gas)
        .and_then(|price| (GAS_PER_BLOB as u128).checked_mul(price))
        .is_some_and(|target_price| {
            BLOB_BASE_COST * parent.base_fee_per_gas as u128 > target_price
        });
    if reserve_binds {
        let delta = (fork.blob_max - fork.blob_target) as u128;
        let scaled = parent.blob_gas_used as u128 * delta / fork.blob_max as u128;
        return u64::try_from(parent.excess_blob_gas as u128 + scaled).ok();
    }
    Some(parent_blob_gas - target)
}

// ---------------------------------------------------------------------------
// Ordered tries, receipts, withdrawals
// ---------------------------------------------------------------------------

/// The root of the trie Ethereum keys by `rlp(index)`: transactions, receipts
/// and withdrawals all hang from one of these.
///
/// No key is a prefix of another — RLP is prefix-free — so every value lands in
/// a leaf and never in a branch's value slot.
pub fn ordered_root(values: &[Vec<u8>]) -> Word32 {
    let mut trie = mpt::Node::Empty;
    for (i, value) in values.iter().enumerate() {
        let mut key = Vec::with_capacity(9);
        rlp::encode_u64(&mut key, i as u64);
        let path = mpt::nibbles_of(&key);
        trie = mpt::insert(trie, &path, value.clone())
            .expect("an ordered trie is built from nothing, so it has no blinded node");
    }
    trie.root()
}

/// One log, as a receipt carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Log {
    pub address: Address20,
    pub topics: Vec<Word32>,
    pub data: Vec<u8>,
}

/// `bloom.py::add_to_bloom`: three bits from `keccak256(entry)`.
fn accrue(bloom: &mut [u8; 256], entry: &[u8]) {
    let hash = keccak(entry);
    for pair in [0, 2, 4] {
        let bit = (((hash[pair] as usize) << 8) | hash[pair + 1] as usize) & 0x7ff;
        bloom[255 - bit / 8] |= 1 << (bit % 8);
    }
}

/// `bloom.py::logs_bloom`: every log's address and topics.
pub fn logs_bloom(logs: &[Log]) -> [u8; 256] {
    let mut bloom = [0u8; 256];
    for log in logs {
        accrue(&mut bloom, &log.address);
        for topic in &log.topics {
            accrue(&mut bloom, topic);
        }
    }
    bloom
}

/// A receipt's EIP-2718 encoding, the receipts trie's value:
/// `[status, cumulative_gas_used, bloom, logs]`, behind the transaction's type
/// byte from type 1 on.
pub fn encode_receipt(
    tx_type: u8,
    succeeded: bool,
    cumulative_gas_used: u64,
    logs: &[Log],
) -> Vec<u8> {
    let mut log_list = Vec::new();
    for log in logs {
        let mut topics = Vec::with_capacity(33 * log.topics.len());
        for topic in &log.topics {
            rlp::encode_bytes(&mut topics, topic);
        }
        let mut fields = Vec::with_capacity(64 + log.data.len());
        rlp::encode_bytes(&mut fields, &log.address);
        rlp::encode_list(&mut fields, &topics);
        rlp::encode_bytes(&mut fields, &log.data);
        rlp::encode_list(&mut log_list, &fields);
    }
    let mut fields = Vec::with_capacity(300 + log_list.len());
    // `succeeded` is a `bool`: RLP's 1 is `0x01` and its 0 the empty string.
    rlp::encode_u64(&mut fields, succeeded as u64);
    rlp::encode_u64(&mut fields, cumulative_gas_used);
    rlp::encode_bytes(&mut fields, &logs_bloom(logs));
    rlp::encode_list(&mut fields, &log_list);
    let mut out = Vec::with_capacity(fields.len() + 6);
    if tx_type != 0 {
        out.push(tx_type);
    }
    rlp::encode_list(&mut out, &fields);
    out
}

/// One EIP-4895 withdrawal, as the payload and the withdrawals trie carry it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Withdrawal {
    pub index: u64,
    pub validator_index: u64,
    pub address: Address20,
    /// Gwei: the consensus layer's unit.
    pub amount: u64,
}

/// `rlp([index, validator_index, address, amount])`, the withdrawals trie's
/// value.
pub fn encode_withdrawal(w: &Withdrawal) -> Vec<u8> {
    let mut fields = Vec::with_capacity(48);
    rlp::encode_u64(&mut fields, w.index);
    rlp::encode_u64(&mut fields, w.validator_index);
    rlp::encode_bytes(&mut fields, &w.address);
    rlp::encode_u64(&mut fields, w.amount);
    let mut out = Vec::with_capacity(fields.len() + 1);
    rlp::encode_list(&mut out, &fields);
    out
}

// ---------------------------------------------------------------------------
// Requests (EIP-7685)
// ---------------------------------------------------------------------------

/// The beacon deposit contract, whose `DepositEvent` logs are EIP-6110's
/// deposit requests. The spec's constant, which `tests-zkevm`'s fixtures share.
pub const DEPOSIT_CONTRACT: Address20 = [
    0x00, 0x00, 0x00, 0x00, 0x21, 0x9a, 0xb5, 0x40, 0x35, 0x6c, 0xbb, 0x83, 0x9c, 0xbe, 0x05, 0x30,
    0x3d, 0x77, 0x05, 0xfa,
];

/// `keccak256("DepositEvent(bytes,bytes,bytes,bytes,bytes)")`.
const DEPOSIT_EVENT: Word32 = [
    0x64, 0x9b, 0xbc, 0x62, 0xd0, 0xe3, 0x13, 0x42, 0xaf, 0xea, 0x4e, 0x5c, 0xd8, 0x2d, 0x40, 0x49,
    0xe7, 0xe1, 0xee, 0x91, 0x2f, 0xc0, 0x88, 0x9a, 0xa7, 0x90, 0x80, 0x3b, 0xe3, 0x90, 0x38, 0xc5,
];

/// `requests.py::extract_deposit_data`: a `DepositEvent`'s ABI payload with
/// its framing checked to the byte and stripped. `None` is a malformed event,
/// which makes the block invalid rather than skipping it.
///
/// Every offset and length word is compared as the whole 32-byte number it is:
/// the guest's `usize` is four bytes, and a word truncated to it would let
/// `2^32 + 160` pass for 160.
fn deposit_data(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() != 576 {
        return None;
    }
    let is = |at: usize, value: u64| -> bool {
        let word = &data[at..at + 32];
        word[..24].iter().all(|b| *b == 0) && word[24..] == value.to_be_bytes()
    };
    // (where the field's length word sits, the length it must hold); the
    // header's five offsets point at those positions, in this order.
    const FIELDS: [(usize, usize); 5] = [(160, 48), (256, 32), (320, 8), (384, 96), (512, 8)];
    for (i, (offset, _)) in FIELDS.iter().enumerate() {
        if !is(32 * i, *offset as u64) {
            return None;
        }
    }
    let mut out = Vec::with_capacity(192);
    for (offset, size) in FIELDS {
        if !is(offset, size as u64) {
            return None;
        }
        out.extend_from_slice(&data[offset + 32..offset + 32 + size]);
    }
    Some(out)
}

/// `requests.py::parse_deposit_requests`: every deposit event among the
/// block's logs, in order, concatenated. `None` is a malformed one.
pub fn deposit_requests(logs: &[Log]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for log in logs {
        if log.address == DEPOSIT_CONTRACT && log.topics.first() == Some(&DEPOSIT_EVENT) {
            out.extend_from_slice(&deposit_data(&log.data)?);
        }
    }
    Some(out)
}

/// `requests.py::compute_requests_hash`: SHA-256 over the SHA-256 of each
/// type-prefixed request, the empty ones having been left out by the caller.
pub fn requests_hash(requests: &[Vec<u8>]) -> Word32 {
    let mut digests = Vec::with_capacity(32 * requests.len());
    for request in requests {
        digests.extend_from_slice(&crate::sha256(request));
    }
    crate::sha256(&digests)
}

/// The length `rlp(block)` would have, for EIP-7934, without building it:
/// `[header, transactions, ommers = [], withdrawals]`, where a legacy
/// transaction is its own list and a typed one is a byte string.
pub fn block_rlp_len(header: &[u8], transactions: &[&[u8]], withdrawals: &[Vec<u8>]) -> usize {
    let mut txs = 0usize;
    for tx in transactions {
        txs += if tx.first().is_some_and(|b| *b >= 0xc0) {
            tx.len()
        } else if tx.len() == 1 && tx[0] < 0x80 {
            1
        } else {
            rlp::header_len(tx.len()) + tx.len()
        };
    }
    let withdrawals: usize = withdrawals.iter().map(Vec::len).sum();
    let payload =
        header.len() + rlp::header_len(txs) + txs + 1 + rlp::header_len(withdrawals) + withdrawals;
    rlp::header_len(payload) + payload
}
