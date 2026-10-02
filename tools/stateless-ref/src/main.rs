//! Regenerates the committed stateless-input SSZ vectors from a second
//! implementation.
//!
//!     cargo run --manifest-path tools/stateless-ref/Cargo.toml
//!
//! `tests-zkevm@v21.0.1` fills only Amsterdam, so the layout the stateless
//! guest also decodes for Osaka, BPO1 and BPO2 — Electra/Fulu's
//! `NewPayloadRequest` — has no release to be held to. This is its oracle:
//! `eth-act/ere-guests`' `stateless-validator-common` at v0.17.1, the input
//! types the zkEVM benchmark's guests decode with, over `libssz` 0.3.0. Its
//! request types and their `hash_tree_root` are used as they are. Its
//! `StatelessInput` is not: v0.17.1 still carries the `public_keys` field
//! `tests-zkevm@v21.0.1` dropped, so the v21 container — request, witness,
//! chain id — is declared here with the same derive, and that derive's decoder
//! is the reference every mutated input is held to.
//!
//! One file, `crates/host/tests/vectors/stateless_ref.txt`, a line per input:
//!
//! ```text
//! <name> <hash_tree_root(request), or `reject`> <schema-prefixed input, hex>
//! ```
//!
//! What the inputs cover: each Electra/Fulu schema id; every list empty; the
//! transaction, withdrawal and request lists either side of EIP-7916's
//! progressive boundaries (1, 5, 21 and 85 elements); one transaction deep
//! enough that its tree needs a zero subtree of depth 12; Gloas beside them,
//! the layout the release already holds the guest to; and the encoding broken
//! six ways, two of them each layout under the other's schema id.
//! Deterministic: same revision in, byte-identical file out.

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use libssz::{SszDecode, SszEncode};
use libssz_derive::{SszDecode, SszEncode};
use libssz_merkle::{HashTreeRoot, Sha2Hasher};
use stateless_validator_common::guest::input::new_payload_request::*;
use stateless_validator_common::guest::input::ExecutionWitness;
use test_support::{to_hex, Rng};

const ERE_GUESTS_REV: &str = "daec35a51ec066cae50636a28311d67cb07bb150";
const SEED: u64 = 20261001;

/// `tests-zkevm@v21.0.1`'s `StatelessInput`, for an Electra/Fulu request.
#[derive(SszEncode, SszDecode)]
struct InputElectraFulu {
    new_payload_request: NewPayloadRequestElectraFulu,
    witness: ExecutionWitness,
    chain_id: u64,
}

/// The same, for a Gloas request.
#[derive(SszEncode, SszDecode)]
struct InputGloas {
    new_payload_request: NewPayloadRequestGloas,
    witness: ExecutionWitness,
    chain_id: u64,
}

const OSAKA: u16 = 0x1201;
const BPO1: u16 = 0x1301;
const BPO2: u16 = 0x1401;
const AMSTERDAM: u16 = 0x1501;

/// How many of each list a request carries.
#[derive(Clone, Copy, Default)]
struct Shape {
    txs: usize,
    tx_len: usize,
    withdrawals: usize,
    hashes: usize,
    requests: [usize; 5],
    extra_data: usize,
}

const TYPICAL: Shape = Shape {
    txs: 3,
    tx_len: 150,
    withdrawals: 3,
    hashes: 2,
    requests: [1, 2, 1, 1, 1],
    extra_data: 7,
};

fn array<const N: usize>(rng: &mut Rng) -> [u8; N] {
    rng.next_bytes(N).try_into().expect("N bytes")
}

fn payload(rng: &mut Rng, shape: Shape) -> ExecutionPayloadV3 {
    ExecutionPayloadV3 {
        parent_hash: array(rng),
        fee_recipient: array(rng),
        state_root: array(rng),
        receipts_root: array(rng),
        logs_bloom: array(rng),
        prev_randao: array(rng),
        block_number: rng.next_u64(),
        gas_limit: rng.next_u64(),
        gas_used: rng.next_u64(),
        timestamp: rng.next_u64(),
        extra_data: rng
            .next_bytes(shape.extra_data)
            .try_into()
            .expect("32 bytes at most"),
        base_fee_per_gas: array(rng),
        block_hash: array(rng),
        transactions: (0..shape.txs)
            .map(|i| rng.next_bytes(shape.tx_len + i).into())
            .collect::<Vec<_>>()
            .into(),
        withdrawals: (0..shape.withdrawals)
            .map(|_| Withdrawal {
                index: rng.next_u64(),
                validator_index: rng.next_u64(),
                address: array(rng),
                amount: rng.next_u64(),
            })
            .collect::<Vec<_>>()
            .into(),
        blob_gas_used: rng.next_u64(),
        excess_blob_gas: rng.next_u64(),
    }
}

fn requests(rng: &mut Rng, counts: [usize; 5]) -> ExecutionRequestsGloas {
    ExecutionRequestsGloas {
        deposits: (0..counts[0])
            .map(|_| DepositRequest {
                pubkey: array(rng),
                withdrawal_credentials: array(rng),
                amount: rng.next_u64(),
                signature: array(rng),
                index: rng.next_u64(),
            })
            .collect::<Vec<_>>()
            .into(),
        withdrawals: (0..counts[1])
            .map(|_| WithdrawalRequest {
                source_address: array(rng),
                validator_pubkey: array(rng),
                amount: rng.next_u64(),
            })
            .collect::<Vec<_>>()
            .into(),
        consolidations: (0..counts[2])
            .map(|_| ConsolidationRequest {
                source_address: array(rng),
                source_pubkey: array(rng),
                target_pubkey: array(rng),
            })
            .collect::<Vec<_>>()
            .into(),
        builder_deposits: (0..counts[3])
            .map(|_| BuilderDepositRequest {
                pubkey: array(rng),
                withdrawal_credentials: array(rng),
                amount: rng.next_u64(),
                signature: array(rng),
            })
            .collect::<Vec<_>>()
            .into(),
        builder_exits: (0..counts[4])
            .map(|_| BuilderExitRequest {
                source_address: array(rng),
                pubkey: array(rng),
            })
            .collect::<Vec<_>>()
            .into(),
    }
}

/// A witness of a few nodes, codes and headers: decoded by both sides, and
/// rooted by neither.
fn witness(rng: &mut Rng) -> ExecutionWitness {
    let mut items = |n: usize, len: usize| -> Vec<Vec<u8>> {
        (0..n).map(|i| rng.next_bytes(len + i)).collect()
    };
    ExecutionWitness {
        state: items(3, 30)
            .into_iter()
            .map(|b| b.try_into().expect("a node"))
            .collect::<Vec<_>>()
            .into(),
        codes: items(2, 20)
            .into_iter()
            .map(|b| b.try_into().expect("a code"))
            .collect::<Vec<_>>()
            .into(),
        headers: items(2, 50)
            .into_iter()
            .map(|b| b.try_into().expect("a header"))
            .collect::<Vec<_>>()
            .try_into()
            .expect("256 headers at most"),
    }
}

/// An Electra/Fulu input and its request's root.
fn electra_fulu(rng: &mut Rng, schema: u16, shape: Shape) -> (Vec<u8>, [u8; 32]) {
    let all = requests(rng, shape.requests);
    let request = NewPayloadRequestElectraFulu {
        execution_payload: payload(rng, shape),
        versioned_hashes: (0..shape.hashes)
            .map(|_| array(rng))
            .collect::<Vec<_>>()
            .into(),
        parent_beacon_block_root: array(rng),
        execution_requests: ExecutionRequestsElectraFulu {
            deposits: all.deposits,
            withdrawals: all.withdrawals,
            consolidations: all.consolidations,
        },
    };
    let root = request.hash_tree_root(&Sha2Hasher);
    let input = InputElectraFulu {
        new_payload_request: request,
        witness: witness(rng),
        chain_id: rng.next_u64(),
    };
    (prefixed(schema, &input.to_ssz()), root)
}

/// A Gloas input and its request's root.
fn gloas(rng: &mut Rng, shape: Shape, access_list: usize) -> (Vec<u8>, [u8; 32]) {
    let v3 = payload(rng, shape);
    let request = NewPayloadRequestGloas {
        execution_payload: ExecutionPayloadV4 {
            parent_hash: v3.parent_hash,
            fee_recipient: v3.fee_recipient,
            state_root: v3.state_root,
            receipts_root: v3.receipts_root,
            logs_bloom: v3.logs_bloom,
            prev_randao: v3.prev_randao,
            block_number: v3.block_number,
            gas_limit: v3.gas_limit,
            gas_used: v3.gas_used,
            timestamp: v3.timestamp,
            extra_data: v3.extra_data,
            base_fee_per_gas: v3.base_fee_per_gas,
            block_hash: v3.block_hash,
            transactions: v3.transactions,
            withdrawals: v3.withdrawals,
            blob_gas_used: v3.blob_gas_used,
            excess_blob_gas: v3.excess_blob_gas,
            block_access_list: rng.next_bytes(access_list).into(),
            slot_number: rng.next_u64(),
        },
        versioned_hashes: (0..shape.hashes)
            .map(|_| array(rng))
            .collect::<Vec<_>>()
            .into(),
        parent_beacon_block_root: array(rng),
        execution_requests: requests(rng, shape.requests),
    };
    let root = request.hash_tree_root(&Sha2Hasher);
    let input = InputGloas {
        new_payload_request: request,
        witness: witness(rng),
        chain_id: rng.next_u64(),
    };
    (prefixed(AMSTERDAM, &input.to_ssz()), root)
}

fn prefixed(schema: u16, body: &[u8]) -> Vec<u8> {
    [&schema.to_be_bytes()[..], body].concat()
}

/// What the reference decoder makes of an input: its request's root, or
/// `reject`.
fn verdict(input: &[u8]) -> String {
    let (schema, body) = input.split_at(2);
    let root = match u16::from_be_bytes([schema[0], schema[1]]) {
        AMSTERDAM => InputGloas::from_ssz_bytes(body)
            .map(|i| i.new_payload_request.hash_tree_root(&Sha2Hasher)),
        _ => InputElectraFulu::from_ssz_bytes(body)
            .map(|i| i.new_payload_request.hash_tree_root(&Sha2Hasher)),
    };
    root.map_or_else(|_| "reject".into(), |root| to_hex(&root))
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
}

fn main() {
    let mut rng = Rng::new(SEED);
    let mut cases: Vec<(String, Vec<u8>, [u8; 32])> = Vec::new();
    let mut push = |name: &str, (input, root): (Vec<u8>, [u8; 32])| {
        cases.push((name.to_string(), input, root));
    };

    for (name, schema) in [("osaka", OSAKA), ("bpo1", BPO1), ("bpo2", BPO2)] {
        push(
            &format!("{name}-typical"),
            electra_fulu(&mut rng, schema, TYPICAL),
        );
    }
    push("bpo2-empty", electra_fulu(&mut rng, BPO2, Shape::default()));
    for n in [2, 5, 6, 21, 22, 86] {
        let shape = Shape {
            txs: n,
            tx_len: 20,
            ..TYPICAL
        };
        push(
            &format!("bpo2-transactions-{n}"),
            electra_fulu(&mut rng, BPO2, shape),
        );
    }
    for n in [5, 6, 21, 22] {
        let shape = Shape {
            withdrawals: n,
            ..TYPICAL
        };
        push(
            &format!("bpo2-withdrawals-{n}"),
            electra_fulu(&mut rng, BPO2, shape),
        );
    }
    for (name, requests) in [
        ("deposits-5", [5, 0, 0, 0, 0]),
        ("withdrawal-requests-6", [0, 6, 0, 0, 0]),
        ("consolidations-21", [0, 0, 21, 0, 0]),
    ] {
        let shape = Shape {
            requests,
            ..TYPICAL
        };
        push(&format!("bpo2-{name}"), electra_fulu(&mut rng, BPO2, shape));
    }
    for n in [5, 6] {
        let shape = Shape {
            hashes: n,
            ..TYPICAL
        };
        push(
            &format!("bpo2-versioned-hashes-{n}"),
            electra_fulu(&mut rng, BPO2, shape),
        );
    }
    let full_extra = Shape {
        extra_data: 32,
        ..TYPICAL
    };
    push(
        "bpo2-extra-data-32",
        electra_fulu(&mut rng, BPO2, full_extra),
    );
    // 1,375 chunks: past the 1 + 4 + ... + 1,024 = 1,365 a tree of zero
    // subtrees up to depth 10 holds, so its last subtree is 4,096 leaves wide.
    let deep = Shape {
        txs: 1,
        tx_len: 44_000,
        ..TYPICAL
    };
    push("bpo2-deep-transaction", electra_fulu(&mut rng, BPO2, deep));
    push("amsterdam-typical", gloas(&mut rng, TYPICAL, 300));
    push("amsterdam-empty", gloas(&mut rng, Shape::default(), 0));

    // The encoding broken, each from a typical input and each a different
    // rule: the two layouts under each other's schema id, and the top-level
    // container's offsets.
    let typical = cases[2].1.clone();
    let amsterdam = cases[cases.len() - 2].1.clone();
    let body = 2;
    let schema = |schema: u16, input: &[u8]| prefixed(schema, &input[body..]);
    let mut first_offset = typical.clone();
    first_offset[body..body + 4].copy_from_slice(&(u32_at(&typical, body) + 4).to_le_bytes());
    let mut decreasing = typical.clone();
    decreasing[body + 4..body + 8].copy_from_slice(&(u32_at(&typical, body) - 1).to_le_bytes());
    let mut past_end = typical.clone();
    past_end[body + 4..body + 8].copy_from_slice(&(typical.len() as u32).to_le_bytes());
    let broken = [
        ("bpo2-schema-on-an-amsterdam-body", schema(BPO2, &amsterdam)),
        (
            "amsterdam-schema-on-a-bpo2-body",
            schema(AMSTERDAM, &typical),
        ),
        ("bpo2-first-offset-past-the-fixed-part", first_offset),
        ("bpo2-offsets-decreasing", decreasing),
        ("bpo2-offset-past-the-end", past_end),
        (
            "bpo2-body-shorter-than-the-fixed-part",
            typical[..body + 15].to_vec(),
        ),
    ];

    let mut out = String::new();
    writeln!(
        out,
        "# hash_tree_root(NewPayloadRequest) of schema-prefixed tests-zkevm@v21.0.1 stateless inputs,"
    )
    .unwrap();
    writeln!(
        out,
        "# by eth-act/ere-guests {ERE_GUESTS_REV} (v0.17.1). Regenerate: cargo run --manifest-path tools/stateless-ref/Cargo.toml"
    )
    .unwrap();
    writeln!(out, "# <name> <root | reject> <input>").unwrap();
    for (name, input, root) in &cases {
        // The reference's decoder agrees with its encoder, or nothing here
        // means anything.
        assert_eq!(verdict(input), to_hex(root), "{name}");
        writeln!(out, "{name} {} {}", to_hex(root), to_hex(input)).unwrap();
    }
    for (name, input) in &broken {
        writeln!(out, "{name} {} {}", verdict(input), to_hex(input)).unwrap();
    }

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/host/tests/vectors/stateless_ref.txt");
    fs::write(&path, &out).expect("writing the vectors");
    println!(
        "wrote crates/host/tests/vectors/stateless_ref.txt ({} inputs, {} bytes)",
        cases.len() + broken.len(),
        out.len()
    );
}
