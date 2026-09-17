//! A synthetic statement for the core's own suites: a key whose circuits are
//! the protocol's and whose digests are consistent, over setup commitments that
//! are distinct 64-byte strings and not points — the core never decodes a
//! point — and a statement shaped to it. Nothing here is proved: the suites
//! that use it test what the core decides before and around a proof.

#![allow(dead_code)]

use constants::family;
use constraints::family_circuit;
use field::Fr;
use gkr_verify::{BoundaryFinals, GkrProof};
use verifier_core::{
    global_commit, identity_digest, srs_digest, PublicInputs, ShardProof, VerifyingKey, VmConfig,
    OPENING_BYTES, SRS_VERIFIER_BYTES, TRIVIAL_TS_WINDOW,
};

pub const ADD: u32 = family::ADD_SUB_LUI_AUIPC;
pub const INIT: u32 = family::INIT_TEARDOWN;
pub const ZERO: u32 = family::ZERO_WINDOWS;

/// A 64-byte string that is not all zero, distinct per `i`.
pub fn blob(i: u32) -> [u8; 64] {
    let mut p = [0u8; 64];
    p[..4].copy_from_slice(&(i + 1).to_le_bytes());
    p[40] = 7;
    p
}

pub fn config() -> VmConfig {
    VmConfig {
        families: vec![(ADD, 1 << 20), (INIT, 1 << 16), (ZERO, 1 << 16)],
        bytecode_size_words: 1 << 20,
    }
}

pub fn vk() -> VerifyingKey {
    let config = config();
    let setup = vec![(0..7).map(blob).collect(), vec![blob(100)], vec![]];
    let srs_verifier = [9u8; SRS_VERIFIER_BYTES];
    VerifyingKey {
        code_version: family::CODE_VERSION,
        entry_pc: 0x1_0000,
        identity: identity_digest(family::CODE_VERSION, &config, 0x1_0000, &setup),
        config,
        setup_commitments: setup,
        srs_verifier,
        srs_digest: srs_digest(&srs_verifier),
        circuits: vec![
            family_circuit(ADD, 20).unwrap(),
            family_circuit(INIT, 16).unwrap(),
            family_circuit(ZERO, 16).unwrap(),
        ],
    }
}

/// The finals of a run that exits with `status`: x10 last written with it.
pub fn finals(status: u32) -> BoundaryFinals {
    let mut b = BoundaryFinals {
        reg_ts: [0; 32],
        pc_ts: 4 * 30,
        reg_values: [0; 31],
    };
    b.reg_ts[10] = 4 * 30 + 3;
    b.reg_values[9] = status;
    b
}

/// One `INIT_TEARDOWN` shard and one `ADD_SUB_LUI_AUIPC` shard, in statement
/// order, with memory commitments of the right widths.
pub fn statement() -> PublicInputs {
    PublicInputs {
        input: vec![1, 2, 3],
        output: vec![],
        exit_status: 42,
        shard_counts: vec![1, 1, 0],
        windows: vec![],
        boundary: finals(42),
        memory_commitments: vec![
            (200..202).map(blob).collect(),
            (300..336).map(blob).collect(),
        ],
        memory_roots: vec![
            [Fr::from_u64(1), Fr::from_u64(2)],
            [Fr::from_u64(3), Fr::from_u64(4)],
        ],
    }
}

/// A proof of the `ADD_SUB_LUI_AUIPC` shard with the right digest and the
/// right widths, and no transitions at all.
pub fn shell(vk: &VerifyingKey, public: &PublicInputs) -> ShardProof {
    ShardProof {
        family: ADD,
        shard_index: 0,
        ts_window: TRIVIAL_TS_WINDOW,
        global_digest: global_commit(vk, public).digest,
        witness_commitments: (400..431).map(blob).collect(),
        outputs: vec![Fr::ZERO; 8],
        gkr: GkrProof { layers: vec![] },
        opening: [3; OPENING_BYTES],
    }
}
