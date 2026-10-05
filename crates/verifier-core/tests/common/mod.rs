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
pub const JBS: u32 = family::JUMP_BRANCH_SLT;
pub const INIT: u32 = family::INIT_TEARDOWN;
pub const ZERO: u32 = family::ZERO_WINDOWS;
pub const PIN: u32 = family::PUBLIC_INPUT;
pub const POUT: u32 = family::PUBLIC_OUTPUT;
pub const ADV: u32 = family::ADVICE_WINDOWS;
pub const KEC: u32 = family::KECCAK_F;
/// The two public value families' pinned height, and the vars of their
/// circuits (`docs/spec/public-values.md` §2).
pub const PUB_VARS: u32 = family::PUBLIC_WINDOW_HEIGHT.trailing_zeros();

/// A 64-byte string that is not all zero, distinct per `i`.
pub fn blob(i: u32) -> [u8; 64] {
    let mut p = [0u8; 64];
    p[..4].copy_from_slice(&(i + 1).to_le_bytes());
    p[40] = 7;
    p
}

/// S-IO's three window families, which are in **every** `VmConfig`
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

/// Their setup lists: empty, all three.
pub fn window_setup() -> Vec<Vec<[u8; 64]>> {
    vec![vec![], vec![], vec![]]
}

pub fn config() -> VmConfig {
    let mut families = vec![(ADD, 1 << 20), (INIT, 1 << 16), (ZERO, 1 << 16)];
    families.extend(window_families(1 << 16));
    VmConfig {
        families,
        bytecode_size_words: 1 << 20,
    }
}

/// The generic table's three commitments every key carries.
pub fn generic_table() -> [[u8; 64]; 3] {
    [blob(20), blob(21), blob(22)]
}

pub fn vk() -> VerifyingKey {
    let config = config();
    let mut setup = vec![(0..7).map(blob).collect(), vec![blob(100)], vec![]];
    setup.extend(window_setup());
    let srs_verifier = [9u8; SRS_VERIFIER_BYTES];
    VerifyingKey {
        code_version: family::CODE_VERSION,
        entry_pc: 0x1_0000,
        identity: identity_digest(family::CODE_VERSION, &config, 0x1_0000, &setup),
        config,
        setup_commitments: setup,
        srs_verifier,
        generic_table: generic_table(),
        srs_digest: srs_digest(&srs_verifier, &generic_table()),
        circuits: {
            let mut c = vec![
                family_circuit(ADD, 20).unwrap(),
                family_circuit(INIT, 16).unwrap(),
                family_circuit(ZERO, 16).unwrap(),
            ];
            c.extend(window_circuits(1 << 16));
            c
        },
    }
}

/// `vk`'s shape with S17's family beside add/sub: its decoded table's seven
/// setup commitments in identity, which with the key's generic table are its
/// ten setup columns.
pub fn jbs_vk() -> VerifyingKey {
    let config = VmConfig {
        families: {
            let mut f = vec![
                (ADD, 1 << 20),
                (JBS, 1 << 20),
                (INIT, 1 << 16),
                (ZERO, 1 << 16),
            ];
            f.extend(window_families(1 << 16));
            f
        },
        bytecode_size_words: 1 << 20,
    };
    let mut setup = vec![
        (0..7).map(blob).collect(),
        (10..17).map(blob).collect(),
        vec![blob(100)],
        vec![],
    ];
    setup.extend(window_setup());
    let srs_verifier = [9u8; SRS_VERIFIER_BYTES];
    VerifyingKey {
        code_version: family::CODE_VERSION,
        entry_pc: 0x1_0000,
        identity: identity_digest(family::CODE_VERSION, &config, 0x1_0000, &setup),
        config,
        setup_commitments: setup,
        srs_verifier,
        generic_table: generic_table(),
        srs_digest: srs_digest(&srs_verifier, &generic_table()),
        circuits: {
            let mut c = vec![
                family_circuit(ADD, 20).unwrap(),
                family_circuit(JBS, 20).unwrap(),
                family_circuit(INIT, 16).unwrap(),
                family_circuit(ZERO, 16).unwrap(),
            ];
            c.extend(window_circuits(1 << 16));
            c
        },
    }
}

/// `vk`'s shape with the `KECCAK_F` delegation family beside add/sub, and the one
/// key fixture whose circuits carry the `XOR8` channel.
///
/// **It exists for the channel's three virtual table addresses.** Since S26d a
/// `ChannelSpec`'s table may name `V[xor8_a]`, `V[xor8_b]` or `V[xor8_out]`, and
/// `types.rs`' private `write_address`/`read_address` carry their own copy of the
/// `VirtualKind` wire tags — a second table beside `constraints::wire`'s. If the
/// two ever disagreed, **no verifying key for a program that hashes could load**,
/// and every other key fixture here would still round-trip: add/sub's channels
/// name `V[range19]`, `V[range16]` and setup columns, and the window families
/// name none at all. This one is the only fast-gate reading of the new arms.
///
/// The family has **no setup column**, so its slot in `setup_commitments` is
/// empty, and it is at `2^16` — the **floor** `family_circuit` gives it, and
/// deliberately not its default, which is `2^18` since S26d. This key is
/// synthetic: it spells its own heights, computes its own identity and SRS
/// digests from them, and reads `DEFAULT_HEIGHTS` nowhere, so the cheapest legal
/// height is the right one here and `2^16` is not a stale literal.
pub fn keccak_vk() -> VerifyingKey {
    let config = VmConfig {
        families: {
            let mut f = vec![
                (ADD, 1 << 20),
                (INIT, 1 << 16),
                (ZERO, 1 << 16),
                (KEC, 1 << 16),
            ];
            f.extend(window_families(1 << 16));
            f
        },
        bytecode_size_words: 1 << 20,
    };
    let mut setup: Vec<Vec<[u8; 64]>> =
        vec![(0..7).map(blob).collect(), vec![blob(100)], vec![], vec![]];
    setup.extend(window_setup());
    let srs_verifier = [9u8; SRS_VERIFIER_BYTES];
    VerifyingKey {
        code_version: family::CODE_VERSION,
        entry_pc: 0x1_0000,
        identity: identity_digest(family::CODE_VERSION, &config, 0x1_0000, &setup),
        config,
        setup_commitments: setup,
        srs_verifier,
        generic_table: generic_table(),
        srs_digest: srs_digest(&srs_verifier, &generic_table()),
        circuits: {
            let mut c = vec![
                family_circuit(ADD, 20).unwrap(),
                family_circuit(INIT, 16).unwrap(),
                family_circuit(ZERO, 16).unwrap(),
                family_circuit(KEC, 16).unwrap(),
            ];
            c.extend(window_circuits(1 << 16));
            c
        },
    }
}

/// A statement shaped to [`jbs_vk`]: one shard of each of its three families
/// that run.
pub fn jbs_statement() -> PublicInputs {
    let mut s = statement();
    // One add/sub, one jump, one init, no zero window, then S-IO's three.
    s.shard_counts = vec![1, 1, 1, 0, 1, 1, 0];
    // Statement order is INIT, ZERO, then ascending, so the jump family's
    // lists go before the two public ones this pushes back on at the end.
    let public = s.memory_commitments.split_off(2);
    let roots = s.memory_roots.split_off(2);
    s.memory_commitments.push((600..621).map(blob).collect());
    s.memory_roots.push([Fr::from_u64(5), Fr::from_u64(6)]);
    s.memory_commitments.extend(public);
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

/// One `INIT_TEARDOWN` shard and one `ADD_SUB_LUI_AUIPC` shard, in statement
/// order, with memory commitments of the right widths: 2 for a window
/// family's frame, and 27 for add/sub's — `1 + 5w` at `w = 5` queries, since
/// deleting the transfer cycle left `arg1`, `arg2` and `ram` unreachable in
/// this family, and one more since S23, `deleg_space`, which carries the
/// requested delegation type's tag into the mirror's leaf.
pub fn statement() -> PublicInputs {
    PublicInputs {
        input: vec![1, 2, 3],
        output: vec![],
        exit_status: 42,
        // One init shard, no zero window, one add/sub shard, then S-IO's
        // three: one public input, one journal, no advice window.
        shard_counts: vec![1, 1, 0, 1, 1, 0],
        windows: vec![],
        boundary: finals(42),
        memory_commitments: vec![
            (200..202).map(blob).collect(),
            (300..327).map(blob).collect(),
            // `PUBLIC_INPUT` commits three columns, the journal two.
            (700..703).map(blob).collect(),
            (710..712).map(blob).collect(),
        ],
        memory_roots: vec![
            [Fr::from_u64(1), Fr::from_u64(2)],
            [Fr::from_u64(3), Fr::from_u64(4)],
            [Fr::from_u64(7), Fr::from_u64(8)],
            [Fr::from_u64(9), Fr::from_u64(10)],
        ],
    }
}

/// A proof of the `ADD_SUB_LUI_AUIPC` shard with the right digest and the
/// right widths, and no transitions at all.
///
/// **Both widths are read off the key's own circuit, not written down here.**
/// The witness count is the frame's `w + 3 = 8` plus the family's own, which
/// carries one delegation-request selector per registered type and so moves
/// with every delegation family the repository registers
/// (`docs/spec/delegation.md` §3). It was the literal 33, with a doc comment
/// saying it would move — and when S26c registered two families it did, which
/// made an honest shell the wrong shape and turned
/// `a_proof_shaped_wrong_is_refused_as_malformed` into a test that refused
/// every case for the *witness* reason whatever it had perturbed. Deriving it
/// is what makes that test about the case it names.
pub fn shell(vk: &VerifyingKey, public: &PublicInputs) -> ShardProof {
    let circuit = vk.circuit(ADD).expect("the add/sub circuit");
    let witness = circuit.artifact.witness.len();
    let outputs = circuit.artifact.outputs.len();
    ShardProof {
        family: ADD,
        shard_index: 0,
        ts_window: TRIVIAL_TS_WINDOW,
        global_digest: global_commit(vk, public).digest,
        witness_commitments: (0..witness as u32).map(|i| blob(400 + i)).collect(),
        outputs: vec![Fr::ZERO; outputs],
        gkr: GkrProof { layers: vec![] },
        opening: [3; OPENING_BYTES],
    }
}
