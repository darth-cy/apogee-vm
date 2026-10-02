//! A JSON-RPC block, as the bytes the chain hashes.
//!
//! JSON-RPC serves a header, a transaction and a receipt as objects of hex
//! fields; the chain commits to their RLP. This is the one place that rebuilds
//! the bytes, and every rebuild has an oracle the node supplied beside it: a
//! header's bytes must hash to its `hash`, a transaction's to its `hash`, and
//! the receipts and withdrawals to the roots in the header. A rebuild that
//! drops or misorders a field does not produce slightly wrong bytes that
//! nothing notices — it produces a hash that matches nothing.
//!
//! Decoding is the guest's (`revm_block::{tx, block}`); this side only encodes,
//! and only from JSON.

use revm_block::block::{Header, Log, Withdrawal};
use revm_block::rlp;
use serde_json::Value;

use crate::rpc::{address_of, bytes_of, u64_of, word_of};

/// A header object, as `eth_getBlockByNumber` serves it, with or without its
/// transactions.
///
/// Every post-Prague field is required. Amsterdam's two are taken when the
/// node serves them, under the names execution-apis gives them.
pub fn header(v: &Value) -> Result<Header, String> {
    let amsterdam = match (v.get("blockAccessListHash"), v.get("slotNumber")) {
        (Some(Value::Null) | None, Some(Value::Null) | None) => (None, None),
        (Some(hash), Some(slot)) => (
            Some(word_of(hash, "the block access list hash")?),
            Some(u64_of(slot, "the slot number")?),
        ),
        _ => return Err("a header carries one of Amsterdam's two fields".into()),
    };
    Ok(Header {
        parent_hash: word_of(&v["parentHash"], "the parent hash")?,
        ommers_hash: word_of(&v["sha3Uncles"], "the ommers hash")?,
        coinbase: address_of(&v["miner"], "the coinbase")?,
        state_root: word_of(&v["stateRoot"], "the state root")?,
        transactions_root: word_of(&v["transactionsRoot"], "the transactions root")?,
        receipts_root: word_of(&v["receiptsRoot"], "the receipts root")?,
        bloom: bytes_of(&v["logsBloom"], "the logs bloom")?
            .try_into()
            .map_err(|_| "the logs bloom is not 256 bytes")?,
        difficulty: word_of(&v["difficulty"], "the difficulty")?,
        number: u64_of(&v["number"], "the number")?,
        gas_limit: u64_of(&v["gasLimit"], "the gas limit")?,
        gas_used: u64_of(&v["gasUsed"], "the gas used")?,
        timestamp: u64_of(&v["timestamp"], "the timestamp")?,
        extra_data: bytes_of(&v["extraData"], "the extra data")?,
        prev_randao: word_of(&v["mixHash"], "prevrandao")?,
        nonce: bytes_of(&v["nonce"], "the nonce")?
            .try_into()
            .map_err(|_| "the nonce is not 8 bytes")?,
        base_fee_per_gas: u64_of(&v["baseFeePerGas"], "the base fee")?,
        withdrawals_root: word_of(&v["withdrawalsRoot"], "the withdrawals root")?,
        blob_gas_used: u64_of(&v["blobGasUsed"], "the blob gas used")?,
        excess_blob_gas: u64_of(&v["excessBlobGas"], "the excess blob gas")?,
        parent_beacon_block_root: word_of(&v["parentBeaconBlockRoot"], "the beacon root")?,
        requests_hash: word_of(&v["requestsHash"], "the requests hash")?,
        block_access_list_hash: amsterdam.0,
        slot_number: amsterdam.1,
    })
}

/// A transaction object as its EIP-2718 bytes: the legacy RLP list, or the type
/// byte and the typed list.
pub fn transaction(v: &Value) -> Result<Vec<u8>, String> {
    let tx_type = match v.get("type") {
        Some(t) => u64_of(t, "the type")?,
        None => 0,
    };
    let mut f = Vec::new();
    let uint = |f: &mut Vec<u8>, key: &str| -> Result<(), String> {
        rlp::encode_uint(f, &word_of(&v[key], key)?);
        Ok(())
    };
    if tx_type != 0 {
        uint(&mut f, "chainId")?;
    }
    uint(&mut f, "nonce")?;
    match tx_type {
        0 | 1 => uint(&mut f, "gasPrice")?,
        _ => {
            uint(&mut f, "maxPriorityFeePerGas")?;
            uint(&mut f, "maxFeePerGas")?;
        }
    }
    uint(&mut f, "gas")?;
    match &v["to"] {
        Value::Null => rlp::encode_bytes(&mut f, &[]),
        to => rlp::encode_bytes(&mut f, &address_of(to, "to")?),
    }
    uint(&mut f, "value")?;
    rlp::encode_bytes(&mut f, &bytes_of(&v["input"], "the input")?);
    if tx_type != 0 {
        f.extend_from_slice(&access_list(&v["accessList"])?);
    }
    if tx_type == 3 {
        uint(&mut f, "maxFeePerBlobGas")?;
        let mut hashes = Vec::new();
        for h in v["blobVersionedHashes"]
            .as_array()
            .ok_or("a blob transaction has no blobVersionedHashes")?
        {
            rlp::encode_bytes(&mut hashes, &word_of(h, "a blob hash")?);
        }
        rlp::encode_list(&mut f, &hashes);
    }
    if tx_type == 4 {
        let mut list = Vec::new();
        for a in v["authorizationList"]
            .as_array()
            .ok_or("a set-code transaction has no authorizationList")?
        {
            let mut fields = Vec::new();
            rlp::encode_uint(
                &mut fields,
                &word_of(&a["chainId"], "an authorization chain id")?,
            );
            rlp::encode_bytes(
                &mut fields,
                &address_of(&a["address"], "an authorization address")?,
            );
            rlp::encode_u64(&mut fields, u64_of(&a["nonce"], "an authorization nonce")?);
            rlp::encode_u64(
                &mut fields,
                u64_of(&a["yParity"], "an authorization y parity")?,
            );
            rlp::encode_uint(&mut fields, &word_of(&a["r"], "an authorization r")?);
            rlp::encode_uint(&mut fields, &word_of(&a["s"], "an authorization s")?);
            rlp::encode_list(&mut list, &fields);
        }
        rlp::encode_list(&mut f, &list);
    }
    if tx_type == 0 {
        uint(&mut f, "v")?;
    } else {
        // `yParity` is the typed field; a node that predates it writes `v`.
        let parity = v.get("yParity").unwrap_or(&v["v"]);
        rlp::encode_u64(&mut f, u64_of(parity, "the y parity")?);
    }
    uint(&mut f, "r")?;
    uint(&mut f, "s")?;
    let mut out = Vec::with_capacity(f.len() + 5);
    if tx_type != 0 {
        out.push(u8::try_from(tx_type).map_err(|_| "a transaction type past 255")?);
    }
    rlp::encode_list(&mut out, &f);
    Ok(out)
}

fn access_list(v: &Value) -> Result<Vec<u8>, String> {
    let mut list = Vec::new();
    for entry in v.as_array().ok_or("the access list is not an array")? {
        let mut keys = Vec::new();
        for key in entry["storageKeys"]
            .as_array()
            .ok_or("an access-list entry has no storageKeys")?
        {
            rlp::encode_bytes(&mut keys, &word_of(key, "an access-list key")?);
        }
        let mut pair = Vec::new();
        rlp::encode_bytes(
            &mut pair,
            &address_of(&entry["address"], "an access-list address")?,
        );
        rlp::encode_list(&mut pair, &keys);
        rlp::encode_list(&mut list, &pair);
    }
    let mut out = Vec::with_capacity(list.len() + 3);
    rlp::encode_list(&mut out, &list);
    Ok(out)
}

/// A withdrawal object.
pub fn withdrawal(v: &Value) -> Result<Withdrawal, String> {
    Ok(Withdrawal {
        index: u64_of(&v["index"], "a withdrawal index")?,
        validator_index: u64_of(&v["validatorIndex"], "a validator index")?,
        address: address_of(&v["address"], "a withdrawal address")?,
        amount: u64_of(&v["amount"], "a withdrawal amount")?,
    })
}

/// A receipt object's type, status, cumulative gas and logs.
pub fn receipt(v: &Value) -> Result<(u8, bool, u64, Vec<Log>), String> {
    let tx_type = u8::try_from(u64_of(&v["type"], "a receipt type")?)
        .map_err(|_| "a receipt type past 255")?;
    let succeeded = match u64_of(&v["status"], "a receipt status")? {
        0 => false,
        1 => true,
        other => return Err(format!("a receipt status of {other}")),
    };
    let mut logs = Vec::new();
    for log in v["logs"].as_array().ok_or("a receipt has no logs array")? {
        logs.push(Log {
            address: address_of(&log["address"], "a log address")?,
            topics: log["topics"]
                .as_array()
                .ok_or("a log has no topics array")?
                .iter()
                .map(|t| word_of(t, "a log topic"))
                .collect::<Result<Vec<_>, String>>()?,
            data: bytes_of(&log["data"], "a log's data")?,
        });
    }
    Ok((
        tx_type,
        succeeded,
        u64_of(&v["cumulativeGasUsed"], "a cumulative gas")?,
        logs,
    ))
}
