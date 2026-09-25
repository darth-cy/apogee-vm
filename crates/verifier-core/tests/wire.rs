//! The core's wire forms, `docs/spec/shard-proof.md` §9, and a key's load
//! rules, §7.2: every value round-trips byte for byte, and every refusal is an
//! `Err` naming what it refused — never a panic.

mod common;

use common::{blob, generic_table, jbs_vk, shell, statement, vk, ADD, JBS};
use constants::family;
use field::Fr;
use gkr_verify::{GkrProof, SumcheckProof};
use verifier_core::{
    identity_digest, srs_digest, PublicInputs, ShardProof, VerifyingKey, VmConfig,
};

fn round_trip_proof() -> ShardProof {
    let mut p = shell(&vk(), &statement());
    p.gkr = GkrProof {
        layers: vec![
            SumcheckProof {
                rounds: vec![[
                    Fr::from_u64(1),
                    Fr::from_u64(2),
                    Fr::from_u64(3),
                    Fr::MINUS_ONE,
                ]],
                final_evals: vec![Fr::from_u64(5), Fr::from_u64(6)],
            },
            SumcheckProof {
                rounds: vec![],
                final_evals: vec![Fr::from_u64(7)],
            },
        ],
    };
    p.outputs = vec![Fr::from_u64(8), Fr::MINUS_ONE];
    p
}

/// Every type round-trips byte for byte, and its encoding is its only one.
#[test]
fn every_value_round_trips_byte_for_byte() {
    let public = statement();
    let bytes = public.to_bytes();
    assert_eq!(PublicInputs::from_bytes(&bytes), Ok(public.clone()));
    assert_eq!(PublicInputs::from_bytes(&bytes).unwrap().to_bytes(), bytes);

    let proof = round_trip_proof();
    let bytes = proof.to_bytes();
    assert_eq!(ShardProof::from_bytes(&bytes), Ok(proof.clone()));
    assert_eq!(ShardProof::from_bytes(&bytes).unwrap().to_bytes(), bytes);

    for key in [vk(), jbs_vk()] {
        assert_eq!(key.check(), Ok(()));
        let bytes = key.to_bytes();
        assert_eq!(VerifyingKey::from_bytes(&bytes), Ok(key.clone()));
        assert_eq!(VerifyingKey::from_bytes(&bytes).unwrap().to_bytes(), bytes);
    }
}

/// The layouts are §9's, read back field by field from the bytes.
#[test]
fn the_layouts_are_the_specs() {
    let proof = round_trip_proof();
    let b = proof.to_bytes();
    let u32_at = |at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
    let u64_at = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
    assert_eq!(u32_at(0), ADD);
    assert_eq!(u32_at(4), 0);
    assert_eq!((u64_at(8), u64_at(16)), (0, 1 << 38));
    assert_eq!(&b[24..56], &proof.global_digest.to_bytes());
    assert_eq!(u32_at(56), 35);
    assert_eq!(&b[60..124], &blob(400));
    let outputs = 60 + 35 * 64;
    assert_eq!(u32_at(outputs), 2);
    let gkr = outputs + 4 + 2 * 32;
    assert_eq!(u32_at(gkr), 2, "two transitions");
    assert_eq!(u32_at(gkr + 4), 1, "transition 0's one round");
    assert_eq!(
        b.len(),
        gkr + 4 + (4 + 4 * 32 + 4 + 2 * 32) + (4 + 4 + 32) + 704
    );
    assert_eq!(&b[b.len() - 704..], &[3u8; 704]);

    let public = statement();
    let b = public.to_bytes();
    // input (4 + 3), output (4), status, counts (4 + 24 — six families since
    // S-IO), windows (4), then the 64 boundary scalars: x10's value is scalar
    // 33 + 9.
    let boundary = 7 + 4 + 4 + (4 + 4 * 6) + 4;
    assert_eq!(u32::from_le_bytes(b[11..15].try_into().unwrap()), 42);
    assert_eq!(
        &b[boundary + 32 * 42..boundary + 32 * 43],
        &Fr::from_u64(42).to_bytes()
    );
    // Four shards: the init window, add/sub, and S-IO's two public windows,
    // whose memory widths are 3 and 2 (`docs/spec/public-values.md` §4).
    assert_eq!(
        b.len(),
        boundary
            + 64 * 32
            + 4
            + (4 + 2 * 64)
            + (4 + 42 * 64)
            + (4 + 3 * 64)
            + (4 + 2 * 64)
            + 4
            + 4 * 64
    );

    // The key: the header up to the circuits, S17's generic table three raw
    // points between the SRS's verifier points and the digest over both.
    let key = jbs_vk();
    let b = key.to_bytes();
    let u32_at = |at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
    assert_eq!(u32_at(0), family::CODE_VERSION);
    let config = key.config.to_bytes();
    assert_eq!(u32_at(4) as usize, config.len());
    assert_eq!(&b[8..8 + config.len()], &config);
    let mut at = 8 + config.len();
    assert_eq!(u32_at(at), 0x1_0000, "the entry pc");
    assert_eq!(&b[at + 4..at + 36], &key.identity.to_bytes());
    at += 36;
    assert_eq!(
        u32_at(at),
        key.config.families.len() as u32,
        "one setup list per family"
    );
    at += 4;
    for list in &key.setup_commitments {
        assert_eq!(u32_at(at) as usize, list.len());
        at += 4;
        for point in list {
            assert_eq!(&b[at..at + 64], point);
            at += 64;
        }
    }
    assert_eq!(&b[at..at + 320], &key.srs_verifier);
    at += 320;
    for point in generic_table() {
        assert_eq!(&b[at..at + 64], &point);
        at += 64;
    }
    assert_eq!(&b[at..at + 32], &key.srs_digest.to_bytes());
    at += 32;
    assert_eq!(
        u32_at(at),
        key.config.families.len() as u32,
        "one circuit per family"
    );
    assert_eq!(u32_at(at + 4), family::ADD_SUB_LUI_AUIPC);
    let artifact = key.circuits[0].artifact.to_bytes();
    assert_eq!(u32_at(at + 8) as usize, artifact.len());
    assert_eq!(&b[at + 12..at + 12 + artifact.len()], &artifact);
}

/// Every refusal of the three readers is an `Err`: truncation — at every
/// length for the statement and the proof, and for the key at every length
/// before its circuits and one in 97 after — a trailing byte, a count the bytes
/// left cannot hold, a field element at the modulus, a boundary scalar out of
/// its range, and a key with a bit flipped.
#[test]
fn the_readers_refuse_rather_than_panic() {
    let public = statement().to_bytes();
    let proof = round_trip_proof().to_bytes();
    for cut in 0..public.len() {
        assert!(
            PublicInputs::from_bytes(&public[..cut]).is_err(),
            "public at {cut}"
        );
    }
    for cut in 0..proof.len() {
        assert!(
            ShardProof::from_bytes(&proof[..cut]).is_err(),
            "proof at {cut}"
        );
    }
    let mut long = public.clone();
    long.push(0);
    assert_eq!(
        PublicInputs::from_bytes(&long),
        Err("bytes follow the value")
    );
    let mut long = proof.clone();
    long.push(0);
    assert_eq!(ShardProof::from_bytes(&long), Err("bytes follow the value"));

    // A count far past the bytes: the witness commitments' count.
    let mut huge = proof.clone();
    huge[56..60].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        ShardProof::from_bytes(&huge),
        Err("a count is longer than the bytes left")
    );
    // The digest at the modulus.
    let mut modulus = proof.clone();
    let p = Fr::MINUS_ONE.to_bytes();
    let mut p_plus = p;
    p_plus[0] += 1;
    modulus[24..56].copy_from_slice(&p_plus);
    assert_eq!(
        ShardProof::from_bytes(&modulus),
        Err("a field element is not canonical")
    );

    // A boundary timestamp of 2^38 and a boundary value of 2^32.
    let boundary = 7 + 4 + 4 + (4 + 4 * 6) + 4;
    let mut ts = public.clone();
    ts[boundary..boundary + 32].copy_from_slice(&Fr::from_u64(1 << 38).to_bytes());
    assert_eq!(
        PublicInputs::from_bytes(&ts),
        Err("a boundary timestamp is not below 2^38")
    );
    let mut ts = public.clone();
    ts[boundary..boundary + 32].copy_from_slice(&Fr::from_u64((1 << 38) - 1).to_bytes());
    assert!(
        PublicInputs::from_bytes(&ts).is_ok(),
        "2^38 − 1 is a timestamp"
    );
    // A timestamp and a value wider than 64 bits, whose low bytes are in
    // range: refused, not truncated to the honest statement.
    for (at, reason) in [
        (boundary + 10 * 32, "a boundary timestamp is not below 2^38"),
        (boundary + 42 * 32, "a boundary value is not below 2^32"),
    ] {
        let mut wide = public.clone();
        wide[at + 20] ^= 1;
        assert_eq!(
            PublicInputs::from_bytes(&wide),
            Err(reason),
            "byte {}",
            at + 20
        );
    }
    let mut v = public.clone();
    let v1 = boundary + 33 * 32;
    v[v1..v1 + 32].copy_from_slice(&Fr::from_u64(1 << 32).to_bytes());
    assert_eq!(
        PublicInputs::from_bytes(&v),
        Err("a boundary value is not below 2^32")
    );

    // Both keys, S17's with its family reading the generic table.
    for honest in [vk(), jbs_vk()] {
        // Every truncation of everything before the circuits, and one cut in
        // every 97 bytes of the circuits; a trailing byte.
        let key = honest.to_bytes();
        let header = {
            let mut bare = honest.clone();
            bare.circuits.clear();
            bare.to_bytes().len() - 4
        };
        let cuts = (0..header + 4).chain((header + 4..key.len()).step_by(97));
        for cut in cuts {
            assert!(
                VerifyingKey::from_bytes(&key[..cut]).is_err(),
                "key at {cut}"
            );
        }
        let mut long = key.clone();
        long.push(0);
        assert!(VerifyingKey::from_bytes(&long).is_err(), "a trailing byte");

        // A flipped bit is refused, never loaded and never a panic: one bit of
        // every byte before the circuits, the bit rotating with the byte, and
        // every bit of one byte in every 1009 of the circuits. A flip in the
        // counts and lengths up front is where a reader would over-read or
        // over-allocate; anywhere else a digest or the registry's bytes no
        // longer match — the generic table's included, since S17's SRS digest
        // covers it.
        let header_flips = (0..header).map(|byte| (byte, byte % 8));
        let circuit_flips = (header..key.len())
            .step_by(1009)
            .flat_map(|byte| (0..8).map(move |bit| (byte, bit)));
        for (byte, bit) in header_flips.chain(circuit_flips) {
            let mut flipped = key.clone();
            flipped[byte] ^= 1 << bit;
            assert!(
                VerifyingKey::from_bytes(&flipped).is_err(),
                "byte {byte} bit {bit} flipped still loads"
            );
        }
        // Every bit of the generic table, the bytes S17 added.
        let table = header - 32 - 3 * 64;
        for byte in table..table + 3 * 64 {
            for bit in 0..8 {
                let mut flipped = key.clone();
                flipped[byte] ^= 1 << bit;
                assert_eq!(
                    VerifyingKey::from_bytes(&flipped).map(|_| ()),
                    Err("the SRS digest is not the digest of the key's SrsVerifier and generic table"
                        .into()),
                    "byte {byte} bit {bit}"
                );
            }
        }
    }
}

/// A key's load rules, §7.2: each edit to an honest key refused, naming it.
#[test]
fn a_key_that_breaks_a_load_rule_is_refused() {
    let honest = vk();
    let mut cases: Vec<(&str, VerifyingKey)> = Vec::new();

    let mut k = honest.clone();
    k.code_version = 1;
    cases.push(("code version 1", k));
    let mut k = honest.clone();
    k.identity.0 += Fr::ONE;
    cases.push(("the identity is not the digest", k));
    let mut k = honest.clone();
    k.entry_pc += 4;
    cases.push(("the identity is not the digest", k));
    let mut k = honest.clone();
    k.setup_commitments[0][3] = blob(999);
    cases.push(("the identity is not the digest", k));
    let mut k = honest.clone();
    k.srs_digest += Fr::ONE;
    cases.push(("the SRS digest is not the digest", k));
    let mut k = honest.clone();
    k.srs_verifier[0] ^= 1;
    cases.push(("the SRS digest is not the digest", k));
    // S17: the generic table under the same digest.
    let mut k = honest.clone();
    k.generic_table[2][5] ^= 1;
    cases.push(("the SRS digest is not the digest", k));
    let mut k = honest.clone();
    k.generic_table.swap(0, 1);
    cases.push(("the SRS digest is not the digest", k));
    let mut k = honest.clone();
    k.circuits.swap(1, 2);
    cases.push(("the key's circuits are not its config's families", k));
    let mut k = honest.clone();
    k.circuits.pop();
    cases.push(("not one circuit per config family", k));
    let mut k = honest.clone();
    k.circuits[0].channels.swap(0, 1);
    cases.push(("the circuit is not the protocol's", k));
    let mut k = honest.clone();
    k.circuits[0].artifact.layers[0].enforcing.pop();
    cases.push(("the circuit is not the protocol's", k));
    let mut k = honest.clone();
    k.circuits[1] = constraints::family_circuit(family::INIT_TEARDOWN, 18).unwrap();
    cases.push(("the circuit is not the protocol's", k));

    // A config the circuits and setup lists still match, at another height:
    // the add/sub family has no circuit below 2^19.
    let mut k = honest.clone();
    k.config.families[0].1 = 1 << 18;
    k.identity = identity_digest(k.code_version, &k.config, k.entry_pc, &k.setup_commitments);
    cases.push(("no circuit proves it at height", k));
    let mut k = honest.clone();
    k.config.families[1].1 = 1 << 18;
    cases.push(("not one a program derives", k));
    // A setup list that is not the artifact's width, the identity recomputed.
    let mut k = honest.clone();
    k.setup_commitments[0].pop();
    k.identity = identity_digest(k.code_version, &k.config, k.entry_pc, &k.setup_commitments);
    cases.push((
        "6 setup commitments and 0 of the generic table for 7 setup columns",
        k,
    ));
    let mut k = honest.clone();
    k.setup_commitments.pop();
    cases.push(("not one setup list per config family", k));
    // S17's family reads the generic table: identity's seven setup
    // commitments are its first seven setup columns, the table the last
    // three, so a setup list of ten — the table carried as a family's own —
    // is refused, and so is one of six.
    let jbs = jbs_vk();
    assert_eq!(jbs.check(), Ok(()));
    let mut k = jbs.clone();
    k.setup_commitments[1].extend(generic_table());
    k.identity = identity_digest(k.code_version, &k.config, k.entry_pc, &k.setup_commitments);
    cases.push((
        "10 setup commitments and 3 of the generic table for 10 setup columns",
        k,
    ));
    let mut k = jbs.clone();
    k.setup_commitments[1].pop();
    k.identity = identity_digest(k.code_version, &k.config, k.entry_pc, &k.setup_commitments);
    cases.push((
        "6 setup commitments and 3 of the generic table for 10 setup columns",
        k,
    ));

    for (want, k) in cases {
        let e = k.check().unwrap_err();
        assert!(e.contains(want), "expected `{want}`: {e}");
        assert!(VerifyingKey::from_bytes(&k.to_bytes()).is_err(), "{want}");
    }

    // A key whose config names a family its circuits do not: add/sub's
    // circuit under a config of S17's family alone, whose circuit exists.
    let mut k = honest.clone();
    k.config = VmConfig {
        families: {
            let mut f = vec![(JBS, 1 << 20), (7, 1 << 16), (8, 1 << 16)];
            f.extend(common::window_families(1 << 16));
            f
        },
        bytecode_size_words: 1 << 20,
    };
    k.identity = identity_digest(k.code_version, &k.config, k.entry_pc, &k.setup_commitments);
    let e = k.check().unwrap_err();
    assert!(
        e.contains("the key's circuits are not its config's families"),
        "{e}"
    );
}

/// The SRS digest is §3's recipe: one `SRS_VERIFIER` bytes message, then, since
/// S17, the generic table as one `GENERIC_TABLE` message of twelve limbs, in a
/// fresh sponge and one raw squeeze — and it moves with every byte of both.
#[test]
fn the_srs_digest_is_the_documented_recipe() {
    let bytes = [5u8; 320];
    let table = generic_table();
    let mut sponge = transcript::Transcript::new();
    sponge.append_bytes(constants::transcript_tags::SRS_VERIFIER, &bytes);
    transcript::append_g1_points(
        &mut sponge,
        constants::transcript_tags::GENERIC_TABLE,
        &table,
    );
    assert_eq!(srs_digest(&bytes, &table), sponge.sample());
    assert_eq!(
        sponge.event_log()[1],
        transcript::TranscriptEvent::Absorb {
            tag: constants::transcript_tags::GENERIC_TABLE,
            n_scalars: 12
        }
    );
    let honest = srs_digest(&bytes, &table);
    for i in 0..bytes.len() {
        let mut moved = bytes;
        moved[i] ^= 1;
        assert_ne!(srs_digest(&moved, &table), honest, "byte {i}");
    }
    for point in 0..3 {
        for i in 0..64 {
            let mut moved = table;
            moved[point][i] ^= 1;
            assert_ne!(srs_digest(&bytes, &moved), honest, "point {point} byte {i}");
        }
    }
}
