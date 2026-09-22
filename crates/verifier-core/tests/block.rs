//! The block types: `docs/spec/block-proof.md` §2, §4 and §6 — the record
//! layout, the wire forms, the structural rule every decoded block keeps, and
//! the public-data API S24 and S27 read.
//!
//! Nothing here is proved. `crates/prover/tests/block.rs` is the statement.

mod common;

use common::{blob, shell, statement, vk, ADD, INIT, JBS, ZERO};
use field::Fr;
use verifier_core::{
    check_ts_windows, BlockProof, BlockReconciliation, ShardRecord, TRIVIAL_TS_WINDOW,
};

/// A block of the synthetic statement: its `INIT_TEARDOWN` shard and its
/// `ADD_SUB_LUI_AUIPC` shard, in statement order, with plausible windows.
fn block() -> BlockProof {
    let vk = vk();
    let public = statement();
    let mut init = shell(&vk, &public);
    init.family = INIT;
    init.witness_commitments = Vec::new();
    init.outputs = vec![Fr::ZERO; 2];
    let mut add = shell(&vk, &public);
    add.ts_window = [4, 400];
    BlockProof {
        config: vk.config.clone(),
        statement: public,
        shards: vec![init, add],
    }
}

/// The record list is statement order, and each record is §2's layout read off
/// the statement and the shard's own proof.
#[test]
fn the_reconciliation_is_the_statement_and_the_proofs() {
    let block = block();
    let records = block.reconciliation().records;
    assert_eq!(records.len(), 2);
    assert_eq!(
        (records[0].family, records[0].shard_index),
        (INIT, 0),
        "the init family leads statement order"
    );
    assert_eq!((records[1].family, records[1].shard_index), (ADD, 0));
    for (i, r) in records.iter().enumerate() {
        assert_eq!(r.ts_window, block.shards[i].ts_window);
        assert_eq!(r.memory_commitments, block.statement.memory_commitments[i]);
        assert_eq!(r.roots, block.statement.memory_roots[i]);
    }
    assert_eq!(records[1].memory_commitments.len(), 42, "add/sub's M width");
}

/// The public-data API: the descriptor, the counts and a family's count, read
/// through a serialized block and nothing else. That is S24's occupancy path
/// and S26's.
#[test]
fn the_public_data_reads_through_the_wire_form() {
    let bytes = block().to_bytes();
    let back = BlockProof::from_bytes(&bytes).expect("a block round-trips");
    assert_eq!(back.to_bytes(), bytes, "byte for byte");
    assert_eq!(back.config(), &vk().config);
    assert_eq!(back.shard_counts(), &[1, 1, 0]);
    assert_eq!(back.shard_count(ADD), 1);
    assert_eq!(back.shard_count(INIT), 1);
    assert_eq!(
        back.shard_count(ZERO),
        0,
        "a family with no shards this run"
    );
    assert_eq!(
        back.shard_count(JBS),
        0,
        "a family the config detaches reads 0, not a panic"
    );
    assert_eq!(back.shard_proofs().len(), 2);
    assert_eq!(back.statement(), &statement());
    assert_eq!(back.reconciliation(), block().reconciliation());
}

/// A decoded block is well-shaped, so its accessors are total: every way the
/// statement and the proofs can be different shard sets is refused at decode.
#[test]
fn a_block_whose_statement_and_proofs_disagree_is_refused() {
    let short_counts = {
        let mut b = block();
        b.statement.shard_counts.pop();
        b
    };
    assert_eq!(
        BlockProof::from_bytes(&short_counts.to_bytes()),
        Err("the block has not one shard count per config family")
    );
    let extra_proof = {
        let mut b = block();
        let last = b.shards[1].clone();
        b.shards.push(last);
        b
    };
    assert_eq!(
        BlockProof::from_bytes(&extra_proof.to_bytes()),
        Err("the block has not one proof, commitment list and root pair per shard")
    );
    let missing_proof = {
        let mut b = block();
        b.shards.pop();
        b
    };
    assert_eq!(
        BlockProof::from_bytes(&missing_proof.to_bytes()),
        Err("the block has not one proof, commitment list and root pair per shard")
    );
    let out_of_order = {
        let mut b = block();
        b.shards.swap(0, 1);
        b
    };
    assert_eq!(
        BlockProof::from_bytes(&out_of_order.to_bytes()),
        Err("the block's proofs are not the statement's shards, in statement order")
    );
    let wrong_index = {
        let mut b = block();
        b.shards[1].shard_index = 1;
        b
    };
    assert_eq!(
        BlockProof::from_bytes(&wrong_index.to_bytes()),
        Err("the block's proofs are not the statement's shards, in statement order")
    );
}

/// The reader is total: a trailing byte, a truncation at every length and a
/// `VmConfig` the derivation could not have produced are each refused, and
/// none of them panics.
#[test]
fn the_block_reader_refuses_everything_it_did_not_write() {
    let bytes = block().to_bytes();
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(BlockProof::from_bytes(&long), Err("bytes follow the value"));
    for cut in 0..bytes.len() {
        assert!(
            BlockProof::from_bytes(&bytes[..cut]).is_err(),
            "a block truncated to {cut} bytes decoded"
        );
    }
    let mut no_windows = block();
    no_windows.config.families.retain(|(f, _)| *f != ZERO);
    assert_eq!(
        BlockProof::from_bytes(&no_windows.to_bytes()),
        Err("the block's VmConfig is refused"),
        "a config without both init families"
    );
}

/// `BlockReconciliation`'s own wire form, the one S27's aggregation guest
/// replays: family, shard index, ts_start, ts_end, the memory commitments in
/// column order, read root, write root.
#[test]
fn the_reconciliation_round_trips_in_its_frozen_layout() {
    let records = block().reconciliation();
    let bytes = records.to_bytes();
    let back = BlockReconciliation::from_bytes(&bytes).expect("it round-trips");
    assert_eq!(back, records);
    assert_eq!(back.to_bytes(), bytes);

    // The layout, field by field, over the second record.
    let one = BlockReconciliation {
        records: vec![ShardRecord {
            family: ADD,
            shard_index: 3,
            ts_window: [4, 0x1_0000_0000],
            memory_commitments: vec![blob(1), blob(2)],
            roots: [Fr::from_u64(11), Fr::from_u64(12)],
        }],
    };
    let b = one.to_bytes();
    assert_eq!(&b[..4], &1u32.to_le_bytes(), "the record count");
    assert_eq!(&b[4..8], &ADD.to_le_bytes());
    assert_eq!(&b[8..12], &3u32.to_le_bytes());
    assert_eq!(&b[12..20], &4u64.to_le_bytes());
    assert_eq!(&b[20..28], &0x1_0000_0000u64.to_le_bytes());
    assert_eq!(&b[28..32], &2u32.to_le_bytes(), "the commitment count");
    assert_eq!(&b[32..96], &blob(1));
    assert_eq!(&b[96..160], &blob(2));
    assert_eq!(&b[160..192], &Fr::from_u64(11).to_bytes());
    assert_eq!(&b[192..224], &Fr::from_u64(12).to_bytes());
    assert_eq!(b.len(), 224);

    let mut long = b.clone();
    long.push(0);
    assert!(BlockReconciliation::from_bytes(&long).is_err());
    for cut in 0..b.len() {
        assert!(
            BlockReconciliation::from_bytes(&b[..cut]).is_err(),
            "a record list truncated to {cut} bytes decoded"
        );
    }
}

/// The window rule is per cycle-owning family, and a block whose records are
/// the honest ones keeps it.
#[test]
fn the_honest_block_keeps_the_window_rule() {
    assert_eq!(check_ts_windows(&block().reconciliation().records), Ok(()));
    // The init shard's trivial window sits inside add/sub's and is exempt.
    let records = block().reconciliation().records;
    assert_eq!(records[0].ts_window, TRIVIAL_TS_WINDOW);
    assert!(records[1].ts_window[1] < TRIVIAL_TS_WINDOW[1]);
}
