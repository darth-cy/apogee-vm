//! A synthetic statement for the core's own suites: a key whose circuits are
//! the protocol's and whose identity is consistent, and a statement shaped to
//! it. Nothing here is proved: the suites that use it test what the core
//! decides before and around a proof.
//!
//! **ALARM — UNFINISHED — WARNING — TODO: NO COMMITMENT SCHEME.** The key
//! carries no setup or generic-table commitment, the statement no memory
//! commitment and the shard no witness commitment or opening: there is none
//! to carry (`docs/architecture.md` §0).

#![allow(dead_code)]

use constants::family;
use constraints::family_circuit;
use field::Fr;
use gkr_verify::{BoundaryFinals, GkrProof};
use verifier_core::{
    global_commit, identity_digest, PublicInputs, ShardProof, VerifyingKey, VmConfig,
    TRIVIAL_TS_WINDOW,
};

pub const ADD: u32 = family::ADD_SUB_LUI_AUIPC;
pub const JBS: u32 = family::JUMP_BRANCH_SLT;
pub const INIT: u32 = family::INIT_TEARDOWN;
pub const ZERO: u32 = family::ZERO_WINDOWS;
pub const PIN: u32 = family::PUBLIC_INPUT;
pub const POUT: u32 = family::PUBLIC_OUTPUT;
pub const ADV: u32 = family::ADVICE_WINDOWS;
/// The two public value families' pinned height, and the vars of their
/// circuits (`docs/spec/public-values.md` §2).
pub const PUB_VARS: u32 = family::PUBLIC_WINDOW_HEIGHT.trailing_zeros();

/// The public and advice window families, which are in **every** `VmConfig`
/// (`docs/spec/public-values.md` §4), at the heights the window rules require.
pub fn window_families(height: u32) -> Vec<(u32, u32)> {
    vec![
        (PIN, family::PUBLIC_WINDOW_HEIGHT),
        (POUT, family::PUBLIC_WINDOW_HEIGHT),
        (ADV, height),
    ]
}

/// Their circuits, in the same order.
pub fn window_circuits(height: u32) -> Vec<constraints::FamilyCircuit> {
    vec![
        family_circuit(PIN, PUB_VARS).unwrap(),
        family_circuit(POUT, PUB_VARS).unwrap(),
        family_circuit(ADV, height.trailing_zeros()).unwrap(),
    ]
}

pub fn config() -> VmConfig {
    let mut families = vec![(ADD, 1 << 20), (INIT, 1 << 16), (ZERO, 1 << 16)];
    families.extend(window_families(1 << 16));
    VmConfig {
        families,
        bytecode_size_words: 1 << 20,
    }
}

/// The key over `config`, its circuits the registry's at those heights.
fn key_over(config: VmConfig) -> VerifyingKey {
    let circuits = config
        .families
        .iter()
        .map(|(f, h)| family_circuit(*f, h.trailing_zeros()).unwrap())
        .collect();
    VerifyingKey {
        code_version: family::CODE_VERSION,
        entry_pc: 0x1_0000,
        identity: identity_digest(family::CODE_VERSION, &config, 0x1_0000),
        config,
        circuits,
    }
}

pub fn vk() -> VerifyingKey {
    key_over(config())
}

/// `vk`'s shape with `JUMP_BRANCH_SLT` beside add/sub.
pub fn jbs_vk() -> VerifyingKey {
    let mut families = vec![
        (ADD, 1 << 20),
        (JBS, 1 << 20),
        (INIT, 1 << 16),
        (ZERO, 1 << 16),
    ];
    families.extend(window_families(1 << 16));
    key_over(VmConfig {
        families,
        bytecode_size_words: 1 << 20,
    })
}

/// A statement shaped to [`jbs_vk`]: one shard of each of its three families
/// that run.
pub fn jbs_statement() -> PublicInputs {
    let mut s = statement();
    // One add/sub, one jump, one init, no zero window, then the public pair
    // and advice.
    s.shard_counts = vec![1, 1, 1, 0, 1, 1, 0];
    // Statement order is INIT, ZERO, then ascending, so the jump family's
    // root pair goes before the two public ones this pushes back on at the end.
    let roots = s.memory_roots.split_off(2);
    s.memory_roots.push([Fr::from_u64(5), Fr::from_u64(6)]);
    s.memory_roots.extend(roots);
    s
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

/// One `INIT_TEARDOWN` shard, one `ADD_SUB_LUI_AUIPC` shard and the two public
/// windows', in statement order, each with its root pair.
pub fn statement() -> PublicInputs {
    PublicInputs {
        input: vec![1, 2, 3],
        output: vec![],
        exit_status: 42,
        // One init shard, no zero window, one add/sub shard, then the window
        // families: one public input, one journal, no advice window.
        shard_counts: vec![1, 1, 0, 1, 1, 0],
        windows: vec![],
        boundary: finals(42),
        memory_roots: vec![
            [Fr::from_u64(1), Fr::from_u64(2)],
            [Fr::from_u64(3), Fr::from_u64(4)],
            [Fr::from_u64(7), Fr::from_u64(8)],
            [Fr::from_u64(9), Fr::from_u64(10)],
        ],
    }
}

/// A proof of the `ADD_SUB_LUI_AUIPC` shard with the right digest and the
/// right output width, and no transitions at all. The width is read off the
/// key's own circuit, not written down here, so an honest shell keeps the
/// circuit's shape whatever the family's layout.
pub fn shell(vk: &VerifyingKey, public: &PublicInputs) -> ShardProof {
    let circuit = vk.circuit(ADD).expect("the add/sub circuit");
    let outputs = circuit.artifact.outputs.len();
    ShardProof {
        family: ADD,
        shard_index: 0,
        ts_window: TRIVIAL_TS_WINDOW,
        global_digest: global_commit(vk, public).digest,
        outputs: vec![Fr::ZERO; outputs],
        gkr: GkrProof { layers: vec![] },
    }
}
