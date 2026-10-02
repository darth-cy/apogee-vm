//! The stateless guest's canonical encodings and signature rules, held to real
//! mainnet blocks and to upstream implementations.
//!
//! Two blocks, both committed as the node served them: **26,057,509** — the
//! pinned mini-block's, 246 transactions of types 0, 2, 3 and 4 — from
//! `vectors/rpc-cache`, and **26,059,929** — 67 transactions and, unlike the
//! other, its receipts — from `vectors/canonical`. Each comes with its parent.
//! Every expected value below is one the node computed: a header's `hash`, a
//! transaction's `hash` and `from`, the header's roots, bloom and gas. A
//! rebuilt encoding that drops or misorders a field matches none of them.
//!
//! What a real block cannot exercise — a high `s`, a non-canonical integer, a
//! header rule broken one at a time — is each a mutation of one of these.

use host::canonical;
use host::rpc::{self, Rpc};
use revm::precompile::secp256k1;
use revm::primitives::alloy_primitives::B512;
use revm::primitives::{Address, B256, U256};
use revm_block::block::{self, Header, HeaderError, Log};
use revm_block::{keccak, tx};
use serde_json::{json, Value};
use std::path::PathBuf;

/// The pinned mini-block's block.
const MINI: u64 = 26_057_509;
/// A block whose receipts are committed beside it.
const RECEIPTS: u64 = 26_059_929;
/// Both blocks are BPO2's: their timestamps are past 1,767,747,671.
const BPO2: u16 = 0x1401;

fn cache(number: u64) -> Rpc {
    let dir = if number == MINI || number == MINI - 1 {
        "rpc-cache"
    } else {
        "canonical"
    };
    Rpc::cached(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/vectors")
            .join(dir),
    )
}

fn block(number: u64, full: bool) -> Value {
    cache(number)
        .call(
            "eth_getBlockByNumber",
            json!([rpc::hex_quantity(number), full]),
        )
        .unwrap_or_else(|e| panic!("block {number}: {e}"))
}

fn word(v: &Value) -> [u8; 32] {
    rpc::word_of(v, "a word").expect("a hex word")
}

/// A header's JSON: the two blocks' are committed in full form, their parents'
/// in the hashes-only form.
fn header_json(number: u64) -> Value {
    block(number, number == MINI || number == RECEIPTS)
}

fn header_and_hash(number: u64) -> (Header, [u8; 32]) {
    let json = header_json(number);
    (
        canonical::header(&json).expect("a header"),
        word(&json["hash"]),
    )
}

#[test]
fn every_header_rebuilds_to_its_hash_and_decodes_back() {
    for number in [MINI, MINI - 1, RECEIPTS, RECEIPTS - 1] {
        let (header, hash) = header_and_hash(number);
        let bytes = header.encode();
        assert_eq!(keccak(&bytes), hash, "block {number}'s header");
        assert_eq!(
            Header::decode(&bytes, false).expect("its own encoding decodes"),
            header,
            "block {number}'s header round-trips"
        );
    }
}

#[test]
fn every_transaction_rebuilds_to_its_hash_and_recovers_to_its_sender() {
    let mut seen = [0usize; 5];
    for number in [MINI, RECEIPTS] {
        for json in block(number, true)["transactions"]
            .as_array()
            .expect("full")
        {
            let bytes = canonical::transaction(json).expect("a transaction");
            assert_eq!(keccak(&bytes), word(&json["hash"]), "{}", json["hash"]);
            let decoded = tx::decode(&bytes).expect("a real transaction decodes");
            seen[decoded.tx_type as usize] += 1;

            let from = rpc::address_of(&json["from"], "from").expect("a sender");
            assert_eq!(tx::sender(&decoded), Some(from), "{}", json["hash"]);
            // Upstream's full recovery, the EVM's own `ecrecover`, agrees.
            assert_eq!(
                upstream(&decoded.signing_hash, &decoded.r, &decoded.s, decoded.y_odd),
                Some(from)
            );

            for auth in &decoded.authorizations {
                let signed =
                    revm::context_interface::transaction::SignedAuthorization::new_unchecked(
                        revm::context_interface::transaction::Authorization {
                            chain_id: U256::from_be_bytes(auth.chain_id),
                            address: Address::from(auth.address),
                            nonce: auth.nonce,
                        },
                        auth.y_parity,
                        U256::from_be_bytes(auth.r),
                        U256::from_be_bytes(auth.s),
                    );
                assert_eq!(
                    tx::authority(auth),
                    signed.recover_authority().ok().map(|a| a.0 .0),
                    "an authorization in {}",
                    json["hash"]
                );
            }
        }
    }
    // The two blocks reach every type but EIP-2930's, which mainnet has all
    // but stopped carrying; its layout is the one type-1 index shift, and
    // `a_transaction_is_decoded_strictly` builds one.
    assert!(
        seen[0] > 0 && seen[2] > 0 && seen[3] > 0 && seen[4] > 0,
        "{seen:?}"
    );
}

/// `revm-precompile`'s `ecrecover`: upstream k256, recover-then-verify, with a
/// high `s` normalized rather than refused.
fn upstream(prehash: &[u8; 32], r: &[u8; 32], s: &[u8; 32], y_odd: bool) -> Option<[u8; 20]> {
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(r);
    sig[32..].copy_from_slice(s);
    secp256k1::ecrecover(&B512::new(sig), y_odd as u8, &B256::new(*prehash))
        .ok()
        .map(|word| word.0[12..].try_into().expect("twenty bytes"))
}

/// A block's header, its transactions as EIP-2718 bytes and its withdrawals'
/// RLP, from its full JSON.
fn body(json: &Value) -> (Header, Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let txs = json["transactions"]
        .as_array()
        .expect("full")
        .iter()
        .map(|t| canonical::transaction(t).expect("a transaction"))
        .collect();
    let withdrawals = json["withdrawals"]
        .as_array()
        .expect("withdrawals")
        .iter()
        .map(|w| block::encode_withdrawal(&canonical::withdrawal(w).expect("a withdrawal")))
        .collect();
    (canonical::header(json).expect("a header"), txs, withdrawals)
}

#[test]
fn the_roots_the_bloom_and_the_gas_are_the_headers() {
    for number in [MINI, RECEIPTS] {
        let (header, txs, withdrawals) = body(&block(number, true));
        assert_eq!(
            block::ordered_root(&txs),
            header.transactions_root,
            "block {number}"
        );
        assert_eq!(
            block::ordered_root(&withdrawals),
            header.withdrawals_root,
            "block {number}"
        );
    }

    let header = canonical::header(&header_json(RECEIPTS)).expect("a header");
    let json = cache(RECEIPTS)
        .call("eth_getBlockReceipts", json!([rpc::hex_quantity(RECEIPTS)]))
        .expect("the committed receipts");
    let mut encoded = Vec::new();
    let mut logs: Vec<Log> = Vec::new();
    let mut gas = 0;
    for receipt in json.as_array().expect("receipts") {
        let (tx_type, succeeded, cumulative, receipt_logs) =
            canonical::receipt(receipt).expect("a receipt");
        // Each receipt's own bloom is the node's too.
        let bloom = rpc::bytes_of(&receipt["logsBloom"], "a bloom").expect("bytes");
        assert_eq!(
            block::logs_bloom(&receipt_logs).as_slice(),
            bloom.as_slice()
        );
        encoded.push(block::encode_receipt(
            tx_type,
            succeeded,
            cumulative,
            &receipt_logs,
        ));
        logs.extend(receipt_logs);
        gas = cumulative;
    }
    assert_eq!(block::ordered_root(&encoded), header.receipts_root);
    assert_eq!(block::logs_bloom(&logs), header.bloom);
    assert_eq!(gas, header.gas_used);
    // No deposit event in this block: its non-empty requests come from the
    // EIP-7002 and EIP-7251 queues, which need execution.
    assert_eq!(block::deposit_requests(&logs), Some(Vec::new()));
}

/// EIP-7934 bounds `rlp(block)`, whose length the node reports as the block's
/// `size`, and `block_rlp_len` computes it without building the encoding. The
/// release's own block-size refusals are 8 MiB by construction, too large for
/// the committed subset, so this is that rule's coverage in CI.
#[test]
fn the_block_size_is_the_node_s() {
    for number in [MINI, RECEIPTS] {
        let json = block(number, true);
        let (header, txs, withdrawals) = body(&json);
        let txs: Vec<&[u8]> = txs.iter().map(Vec::as_slice).collect();
        assert_eq!(
            block::block_rlp_len(&header.encode(), &txs, &withdrawals) as u64,
            rpc::u64_of(&json["size"], "a size").expect("a quantity"),
            "block {number}"
        );
    }
}

#[test]
fn each_header_follows_its_parent() {
    let fork = block::fork(BPO2).expect("BPO2 is a schema this guest validates");
    for number in [MINI, RECEIPTS] {
        let (header, _) = header_and_hash(number);
        let (parent, parent_hash) = header_and_hash(number - 1);
        assert_eq!(
            block::validate_header(&fork, &parent, &parent_hash, &header),
            Ok(())
        );
    }
}

#[test]
fn every_header_rule_refuses_its_own_mutation() {
    let fork = block::fork(BPO2).expect("BPO2");
    let (header, _) = header_and_hash(RECEIPTS);
    let (parent, parent_hash) = header_and_hash(RECEIPTS - 1);
    type Mutation = fn(&mut Header);
    let cases: [(Mutation, HeaderError); 12] = [
        (|h| h.number = 0, HeaderError::NumberZero),
        (|h| h.excess_blob_gas += 1, HeaderError::ExcessBlobGas),
        (
            |h| h.gas_used = h.gas_limit + 1,
            HeaderError::GasUsedOverLimit,
        ),
        (
            |h| h.gas_limit += h.gas_limit / 1024 + 1,
            HeaderError::GasLimit,
        ),
        (|h| h.base_fee_per_gas += 1, HeaderError::BaseFee),
        (|h| h.timestamp = 0, HeaderError::Timestamp),
        (|h| h.number += 1, HeaderError::Number),
        (|h| h.extra_data = vec![0; 33], HeaderError::ExtraData),
        (|h| h.difficulty[31] = 1, HeaderError::Difficulty),
        (|h| h.nonce[7] = 1, HeaderError::Nonce),
        (|h| h.ommers_hash[0] ^= 1, HeaderError::OmmersHash),
        (|h| h.parent_hash[0] ^= 1, HeaderError::ParentHash),
    ];
    for (mutate, expected) in cases {
        let mut bad = header.clone();
        mutate(&mut bad);
        assert_eq!(
            block::validate_header(&fork, &parent, &parent_hash, &bad),
            Err(expected)
        );
    }
}

#[test]
fn the_signature_rules_are_the_spec_s() {
    use k256::ecdsa::SigningKey;
    // n, secp256k1's order, big-endian.
    let n = U256::from_be_bytes(
        test_support::hex_to_32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
            .expect("n"),
    );
    let mut rng = test_support::Rng::new(0x7702);
    for _ in 0..32 {
        let key = SigningKey::from_bytes(&rng.next_le32().into()).expect("a nonzero key below n");
        let prehash = rng.next_le32();
        let (sig, id) = key.sign_prehash_recoverable(&prehash).expect("signs");
        let point = key.verifying_key().to_encoded_point(false);
        let address: [u8; 20] = keccak(&point.as_bytes()[1..])[12..].try_into().expect("20");
        let r: [u8; 32] = sig.r().to_bytes().into();
        let s: [u8; 32] = sig.s().to_bytes().into();
        let odd = id.is_y_odd();

        assert_eq!(tx::recover(&prehash, &r, &s, odd), Some(address));
        assert_eq!(upstream(&prehash, &r, &s, odd), Some(address));
        // EIP-2: the same signature with `s` mirrored to the high half is a
        // second encoding of it. The precompile normalizes it back; a
        // transaction and an authorization may not carry it.
        let high: [u8; 32] = (n - U256::from_be_bytes(s)).to_be_bytes();
        assert_eq!(upstream(&prehash, &r, &high, !odd), Some(address));
        assert_eq!(tx::recover(&prehash, &r, &high, !odd), None);
        // `r` and `s` are each in `[1, n)`.
        assert_eq!(tx::recover(&prehash, &[0; 32], &s, odd), None);
        assert_eq!(tx::recover(&prehash, &r, &[0; 32], odd), None);
        assert_eq!(tx::recover(&prehash, &n.to_be_bytes(), &s, odd), None);
    }
}

#[test]
fn a_transaction_is_decoded_strictly() {
    let json = block(MINI, true);
    let txs = json["transactions"].as_array().expect("full");
    let bytes_of_type = |t: u8| {
        txs.iter()
            .map(|j| canonical::transaction(j).expect("a transaction"))
            .find(|b| (b[0] >= 0xc0 && t == 0) || b[0] == t)
            .expect("the block has one")
    };
    let legacy = bytes_of_type(0);
    let blob = bytes_of_type(3);

    let mut trailing = blob.clone();
    trailing.push(0);
    let mut unknown = blob.clone();
    unknown[0] = 5;
    assert!(tx::decode(&blob).is_ok() && tx::decode(&legacy).is_ok());
    for bad in [Vec::new(), vec![0x80], trailing, unknown] {
        assert!(tx::decode(&bad).is_err(), "{bad:02x?}");
    }

    // A legacy `v` of 29 is neither pre- nor post-EIP-155.
    let items = revm_block::rlp::list_items(&legacy).expect("a list");
    let mut fields = Vec::new();
    for (i, item) in items.iter().enumerate() {
        if i == 6 {
            revm_block::rlp::encode_u64(&mut fields, 29);
        } else {
            fields.extend_from_slice(item.whole);
        }
    }
    let mut bad_v = Vec::new();
    revm_block::rlp::encode_list(&mut bad_v, &fields);
    assert!(tx::decode(&bad_v).is_err());

    // A type-1 transaction — the layout neither block carries — rebuilt from a
    // legacy one's fields: chain id, nonce, gas price, gas, to, value, data,
    // an empty access list. Its signature is the legacy one's and so recovers
    // to someone else, which is not this test's business.
    let mut fields = Vec::new();
    revm_block::rlp::encode_u64(&mut fields, 1);
    for item in &items[..6] {
        fields.extend_from_slice(item.whole);
    }
    fields.push(0xc0);
    fields.extend_from_slice(&[0x80]);
    for item in &items[7..] {
        fields.extend_from_slice(item.whole);
    }
    let mut type1 = vec![1u8];
    revm_block::rlp::encode_list(&mut type1, &fields);
    let decoded = tx::decode(&type1).expect("a type-1 transaction decodes");
    assert_eq!((decoded.tx_type, decoded.chain_id), (1, Some(1)));
    assert!(decoded.access_list.is_empty() && decoded.priority_fee.is_none());

    // A blob transaction's destination may not be empty.
    let blob_items = revm_block::rlp::list_items(&blob[1..]).expect("a list");
    let mut fields = Vec::new();
    for (i, item) in blob_items.iter().enumerate() {
        if i == 5 {
            fields.push(0x80);
        } else {
            fields.extend_from_slice(item.whole);
        }
    }
    let mut no_to = vec![3u8];
    revm_block::rlp::encode_list(&mut no_to, &fields);
    assert!(tx::decode(&no_to).is_err());

    // A leading zero is a second encoding of the same nonce.
    let mut fields = Vec::new();
    for (i, item) in items.iter().enumerate() {
        if i == 0 {
            let nonce = revm_block::rlp::bytes(item).expect("bytes");
            let mut padded = vec![0u8];
            padded.extend_from_slice(nonce);
            revm_block::rlp::encode_bytes(&mut fields, &padded);
        } else {
            fields.extend_from_slice(item.whole);
        }
    }
    let mut padded = Vec::new();
    revm_block::rlp::encode_list(&mut padded, &fields);
    assert!(tx::decode(&padded).is_err());
}

#[test]
fn a_deposit_event_is_parsed_to_the_byte() {
    // A `DepositEvent` laid out as the deposit contract emits it: five offsets,
    // then five length-prefixed fields padded to 32 bytes.
    let mut rng = test_support::Rng::new(6110);
    let fields: Vec<Vec<u8>> = [48, 32, 8, 96, 8]
        .iter()
        .map(|n| rng.next_bytes(*n))
        .collect();
    let mut data = vec![0u8; 576];
    for (i, (offset, field)) in [160usize, 256, 320, 384, 512]
        .iter()
        .zip(&fields)
        .enumerate()
    {
        data[32 * i + 24..32 * i + 32].copy_from_slice(&(*offset as u64).to_be_bytes());
        data[offset + 24..offset + 32].copy_from_slice(&(field.len() as u64).to_be_bytes());
        data[offset + 32..offset + 32 + field.len()].copy_from_slice(field);
    }
    let log = |data: Vec<u8>| Log {
        address: block::DEPOSIT_CONTRACT,
        topics: vec![keccak(b"DepositEvent(bytes,bytes,bytes,bytes,bytes)")],
        data,
    };
    assert_eq!(
        block::deposit_requests(&[log(data.clone())]),
        Some(fields.concat())
    );
    // An offset of `2^32 + 160` is 160 to a four-byte `usize`, and not to the spec.
    let mut wide = data.clone();
    wide[27] = 1;
    assert_eq!(block::deposit_requests(&[log(wide)]), None);
    let mut short = data;
    short.pop();
    assert_eq!(block::deposit_requests(&[log(short)]), None);
}

#[test]
fn the_blob_price_is_eip_4844_s_and_saturates_rather_than_panics() {
    let fork = block::fork(BPO2).expect("BPO2");
    for excess in (0..400_000_000u64).step_by(9_999_991) {
        assert_eq!(
            block::blob_gas_price(&fork, excess),
            Some(revm::context_interface::block::calc_blob_gasprice(
                excess,
                fork.blob_fraction
            )),
        );
    }
    // revm's own is unchecked and would overflow-panic here.
    assert_eq!(block::blob_gas_price(&fork, u64::MAX), None);
}
