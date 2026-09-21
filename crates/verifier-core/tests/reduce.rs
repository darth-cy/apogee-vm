//! What `reduce_shard` decides before and around a proof,
//! `docs/spec/shard-proof.md` §2 and §6: the global transcript's messages in
//! their frozen order, and every `Statement` and `Malformed` refusal — each
//! the class its step names, none a panic. The proofs themselves are
//! `crates/prover/tests` and `crates/checker/tests/tamper.rs`.

mod common;

use common::{blob, jbs_statement, jbs_vk, shell, statement, vk, ADD, INIT, JBS, ZERO};
use constants::transcript_tags as tags;
use field::Fr;
use gkr_verify::SumcheckProof;
use transcript::TranscriptEvent::{Absorb, Challenge};
use verifier_core::{
    derive_global_phase, global_commit, memory_slots, reduce_shard, shard_challenges,
    shard_transcript, srs_digest, statement_shards, verify_global_memory, VerifyError,
    TRIVIAL_TS_WINDOW,
};

fn refusal(
    vk: &verifier_core::VerifyingKey,
    proof: &verifier_core::ShardProof,
    public: &verifier_core::PublicInputs,
) -> VerifyError {
    match reduce_shard(vk, proof, public) {
        Ok(_) => panic!("refused"),
        Err(e) => e,
    }
}

/// G1 to G11, event for event: the suite, the SRS digest, the descriptor's
/// three messages, the identity, the I/O digest's bytes, one group per config
/// family — `INIT_TEARDOWN`, `ZERO_WINDOWS`, then the rest — each a header and
/// one list per shard, the boundary, four memory challenges, the digest.
#[test]
fn the_global_transcript_is_the_frozen_order() {
    let (key, public) = (vk(), statement());
    let g = global_commit(&key, &public);
    let log: Vec<_> = g.transcript.event_log().to_vec();
    let absorb = |tag, n_scalars| Absorb { tag, n_scalars };
    let mut want = vec![
        absorb(tags::PROTOCOL_SUITE, 1),
        absorb(tags::SRS_DIGEST, 1),
        absorb(tags::VM_CONFIG, 7),
        absorb(tags::SHARD_COUNTS, 3),
        absorb(tags::MEMORY_WINDOWS, 0),
        absorb(tags::PROGRAM_IDENTITY, 1),
        absorb(tags::PUBLIC_INPUTS, 2),
        absorb(tags::MEMORY_GROUP, 2),
        absorb(tags::COMMITMENT, 4 * 2),
        absorb(tags::MEMORY_GROUP, 2),
        absorb(tags::MEMORY_GROUP, 2),
        absorb(tags::COMMITMENT, 4 * 41),
        absorb(tags::MEMORY_BOUNDARY, 64),
    ];
    want.extend(
        [Challenge {
            tag: tags::MEMORY_CHALLENGE,
        }; 4],
    );
    want.push(Challenge {
        tag: tags::GLOBAL_STATE_DIGEST,
    });
    assert_eq!(log, want);
    assert_eq!(
        statement_shards(&key.config, &public.shard_counts),
        vec![(INIT, 0), (ADD, 0)]
    );

    // Every statement field moves the digest but two: the roots, computed
    // after it and bound by each shard's own proof, and the exit status, bound
    // through x10's final value at step 10.
    let digest = g.digest;
    let moved = |edit: fn(&mut verifier_core::PublicInputs)| {
        let mut p = statement();
        edit(&mut p);
        global_commit(&key, &p).digest != digest
    };
    assert!(moved(|p| p.input.push(0)));
    assert!(moved(|p| p.output.push(0)));
    assert!(moved(|p| p.boundary.reg_ts[3] += 1));
    assert!(moved(|p| p.boundary.pc_ts += 1));
    assert!(moved(|p| p.boundary.reg_values[0] += 1));
    assert!(moved(|p| p.memory_commitments[1][40] = blob(999)));
    assert!(moved(|p| p.memory_commitments[1].swap(0, 1)));
    assert!(moved(|p| p.memory_commitments.swap(0, 1)));
    assert!(moved(|p| {
        p.shard_counts[2] = 1;
        p.windows.push(1);
        p.memory_commitments.insert(1, vec![blob(500), blob(501)]);
    }));
    assert!(moved(|p| p.windows.push(1)));
    assert!(!moved(|p| p.memory_roots[0][0] += Fr::ONE));
    assert!(!moved(|p| p.exit_status += 1));
    let mut k = vk();
    k.srs_digest += Fr::ONE;
    assert_ne!(global_commit(&k, &public).digest, digest);
    let mut k = vk();
    k.identity.0 += Fr::ONE;
    assert_ne!(global_commit(&k, &public).digest, digest);
}

/// S17: the generic table is bound through the SRS digest, which G2 absorbs
/// before every challenge of the statement and of every shard seeded from it.
/// A key with S17's family has S16's schedule exactly, and the statement's
/// digest moves with each of the table's points and with their order, once
/// the key's SRS digest is recomputed over them — and a key whose table moved
/// without it does not load.
#[test]
fn the_generic_table_is_bound_through_the_srs_digest() {
    let (key, public) = (jbs_vk(), jbs_statement());
    assert_eq!(key.check(), Ok(()));
    let g = global_commit(&key, &public);
    let log = g.transcript.event_log();
    assert_eq!(
        &log[..3],
        &[
            Absorb {
                tag: tags::PROTOCOL_SUITE,
                n_scalars: 1
            },
            Absorb {
                tag: tags::SRS_DIGEST,
                n_scalars: 1
            },
            Absorb {
                tag: tags::VM_CONFIG,
                n_scalars: 9
            },
        ]
    );
    assert!(log.iter().all(|e| *e
        != Absorb {
            tag: tags::GENERIC_TABLE,
            n_scalars: 12
        }));
    assert_eq!(
        statement_shards(&key.config, &public.shard_counts),
        vec![(INIT, 0), (ADD, 0), (JBS, 0)]
    );
    let moved = |k: &mut verifier_core::VerifyingKey| {
        assert!(k.check().is_err(), "a moved table without its digest loads");
        k.srs_digest = srs_digest(&k.srs_verifier, &k.generic_table);
        assert_eq!(k.check(), Ok(()));
        global_commit(k, &public).digest
    };
    for i in 0..3 {
        let mut k = jbs_vk();
        k.generic_table[i] = blob(900 + i as u32);
        assert_ne!(moved(&mut k), g.digest, "point {i}");
    }
    let mut k = jbs_vk();
    k.generic_table.swap(0, 2);
    assert_ne!(moved(&mut k), g.digest, "the order");
}

/// S1 to S4: the seed, the window, the witness commitments as one message,
/// then `g` and `β`.
#[test]
fn a_shard_transcript_starts_with_its_seed_its_window_and_its_commitments() {
    let (t, g, beta) = shard_transcript(
        Fr::from_u64(7),
        ADD,
        0,
        TRIVIAL_TS_WINDOW,
        &[blob(1), blob(2)],
    );
    assert_ne!(g, beta);
    assert_eq!(
        t.event_log(),
        &[
            Absorb {
                tag: tags::SHARD_SEED,
                n_scalars: 3
            },
            Absorb {
                tag: tags::SHARD_TS_WINDOW,
                n_scalars: 2
            },
            Absorb {
                tag: tags::COMMITMENT,
                n_scalars: 8
            },
            Challenge {
                tag: tags::LOOKUP_CHALLENGE
            },
            Challenge {
                tag: tags::LOOKUP_CHALLENGE
            },
        ]
    );
    // Each part of the seed moves the challenges.
    let (_, g2, _) = shard_transcript(
        Fr::from_u64(8),
        ADD,
        0,
        TRIVIAL_TS_WINDOW,
        &[blob(1), blob(2)],
    );
    let (_, g3, _) = shard_transcript(
        Fr::from_u64(7),
        INIT,
        0,
        TRIVIAL_TS_WINDOW,
        &[blob(1), blob(2)],
    );
    let (_, g4, _) = shard_transcript(
        Fr::from_u64(7),
        ADD,
        1,
        TRIVIAL_TS_WINDOW,
        &[blob(1), blob(2)],
    );
    let (_, g5, _) = shard_transcript(Fr::from_u64(7), ADD, 0, [0, 4], &[blob(1), blob(2)]);
    let (_, g6, _) = shard_transcript(Fr::from_u64(7), ADD, 0, TRIVIAL_TS_WINDOW, &[blob(1)]);
    for other in [g2, g3, g4, g5, g6] {
        assert_ne!(other, g);
    }
}

/// `g` then `β`: the first and the second `LOOKUP_CHALLENGE` squeeze after
/// the seed, the window and the commitments, replayed by hand.
#[test]
fn g_is_the_first_lookup_squeeze_and_beta_the_second() {
    let commitments = [blob(1), blob(2)];
    let digest = Fr::from_u64(7);
    let (_, g, beta) = shard_transcript(digest, ADD, 3, TRIVIAL_TS_WINDOW, &commitments);
    let mut t = transcript::Transcript::new();
    t.append_scalars(
        tags::SHARD_SEED,
        &[digest, Fr::from_u64(ADD as u64), Fr::from_u64(3)],
    );
    t.append_scalars(tags::SHARD_TS_WINDOW, &[Fr::ZERO, Fr::from_u64(1 << 38)]);
    transcript::append_g1_points(&mut t, tags::COMMITMENT, &commitments);
    assert_eq!(g, t.challenge_scalar(tags::LOOKUP_CHALLENGE));
    assert_eq!(beta, t.challenge_scalar(tags::LOOKUP_CHALLENGE));
}

/// The challenges a shard's circuit reads (§4): slots 1 to 4 from the memory
/// challenges; the window constant at the shard's own window — 0 for
/// `INIT_TEARDOWN`, `windows[index]` for each `ZERO_WINDOWS` shard, and none
/// for an execution family; and the LogUp slots from `g` and `β`.
#[test]
fn a_shard_reads_the_window_constant_of_its_own_window() {
    use constants::challenge_slot as slot;
    let key = vk();
    let memory = [11, 12, 13, 14].map(Fr::from_u64);
    let (g, beta) = (Fr::from_u64(21), Fr::from_u64(22));
    let windows = [3, 9];
    let expected = |circuit: &constraints::FamilyCircuit, window: u32| {
        let mut want = gkr_verify::window_challenges(
            &memory_slots(&memory),
            window,
            circuit.artifact.trace_vars,
        );
        gkr_verify::insert_lookup_challenges(&mut want, g, beta, &circuit.artifact);
        want
    };
    let (add, init, zero) = (&key.circuits[0], &key.circuits[1], &key.circuits[2]);
    assert_eq!((init.family, zero.family), (INIT, ZERO));

    let first = shard_challenges(zero, 0, &windows, &memory, g, beta);
    let second = shard_challenges(zero, 1, &windows, &memory, g, beta);
    assert_eq!(first, expected(zero, 3));
    assert_eq!(second, expected(zero, 9));
    assert_ne!(
        first.get(slot::MEM_WINDOW_CONSTANT),
        second.get(slot::MEM_WINDOW_CONSTANT),
        "two windows, two constants"
    );
    assert_eq!(
        shard_challenges(init, 0, &windows, &memory, g, beta),
        expected(init, 0)
    );

    let own = shard_challenges(add, 0, &windows, &memory, g, beta);
    assert_eq!(own.get(slot::MEM_WINDOW_CONSTANT), None);
    for (s, v) in [
        slot::MEM_GAMMA,
        slot::MEM_ALPHA_ADDR,
        slot::MEM_ALPHA_TS,
        slot::MEM_ALPHA_VAL,
    ]
    .into_iter()
    .zip(memory)
    {
        assert_eq!(own.get(s), Some(v));
    }
    assert_eq!(own.get(slot::LOOKUP_G), Some(g));
    assert_eq!(own.get(slot::LOOKUP_BETA), Some(beta));
}

/// Steps 1 to 5: a statement the key does not describe, or not the proof's, is
/// refused as `Statement`, each rule by name, before anything is indexed.
#[test]
fn a_statement_the_key_does_not_describe_is_refused_as_statement() {
    let key = vk();
    let honest = statement();
    let proof = shell(&key, &honest);
    let mut cases: Vec<(
        &str,
        verifier_core::VerifyingKey,
        verifier_core::PublicInputs,
        verifier_core::ShardProof,
    )> = Vec::new();

    let mut p = honest.clone();
    p.shard_counts.pop();
    cases.push((
        "not one shard count per config family",
        key.clone(),
        p,
        proof.clone(),
    ));
    let mut k = key.clone();
    k.circuits.pop();
    cases.push((
        "the key's circuits are not its config's families",
        k,
        honest.clone(),
        proof.clone(),
    ));
    // A key edited in memory to hold one setup list too few: refused here,
    // not by a panic where step 11 indexes the lists.
    let mut k = key.clone();
    k.setup_commitments.pop();
    cases.push((
        "the key's circuits are not its config's families",
        k,
        honest.clone(),
        proof.clone(),
    ));
    let mut k = key.clone();
    k.config.families.swap(1, 2);
    cases.push((
        "the key's circuits are not its config's families",
        k,
        honest.clone(),
        proof.clone(),
    ));
    let mut p = honest.clone();
    p.shard_counts[1] = 2;
    cases.push((
        "INIT_TEARDOWN proves exactly one shard",
        key.clone(),
        p,
        proof.clone(),
    ));
    let mut p = honest.clone();
    p.shard_counts[2] = 1;
    cases.push((
        "the window list has one id per ZERO_WINDOWS shard",
        key.clone(),
        p,
        proof.clone(),
    ));
    let mut p = honest.clone();
    p.shard_counts[2] = 2;
    p.windows = vec![5, 5];
    cases.push((
        "the window ids are strictly increasing",
        key.clone(),
        p,
        proof.clone(),
    ));
    let mut p = honest.clone();
    p.shard_counts[2] = 1;
    p.windows = vec![1 << 13];
    cases.push((
        "every window id is in [1, 2^29 / h - 1]",
        key.clone(),
        p,
        proof.clone(),
    ));
    let mut p = honest.clone();
    p.shard_counts[0] = 2;
    cases.push((
        "not one commitment list per shard",
        key.clone(),
        p,
        proof.clone(),
    ));
    let mut p = honest.clone();
    p.shard_counts[0] = u32::MAX;
    cases.push((
        "not one commitment list per shard",
        key.clone(),
        p,
        proof.clone(),
    ));
    let mut p = honest.clone();
    p.memory_roots.pop();
    cases.push(("not one root pair per shard", key.clone(), p, proof.clone()));
    let mut p = honest.clone();
    p.memory_commitments[0].pop();
    cases.push((
        "not its family's memory width",
        key.clone(),
        p,
        proof.clone(),
    ));
    let mut p = honest.clone();
    p.memory_commitments.swap(0, 1);
    cases.push((
        "not its family's memory width",
        key.clone(),
        p,
        proof.clone(),
    ));
    // Step 4 since S20: a window is `[start, end)` inside the clock. Which
    // windows a block admits is `check_ts_windows`, which needs every shard.
    let mut q = proof.clone();
    q.ts_window = [5, 4];
    cases.push((
        "the time window is not [start, end) in the clock",
        key.clone(),
        honest.clone(),
        q,
    ));
    let mut q = proof.clone();
    q.ts_window = [0, (1 << 38) + 1];
    cases.push((
        "the time window is not [start, end) in the clock",
        key.clone(),
        honest.clone(),
        q,
    ));
    // Everything the digest binds.
    let mut p = honest.clone();
    p.output.push(1);
    cases.push(("made for another statement", key.clone(), p, proof.clone()));
    let mut p = honest.clone();
    p.memory_commitments[1].swap(0, 1);
    cases.push(("made for another statement", key.clone(), p, proof.clone()));
    let mut k = key.clone();
    k.srs_digest += Fr::ONE;
    cases.push((
        "made for another statement",
        k,
        honest.clone(),
        proof.clone(),
    ));
    let mut k = key.clone();
    k.config.bytecode_size_words += 1;
    cases.push((
        "made for another statement",
        k,
        honest.clone(),
        proof.clone(),
    ));
    let mut q = proof.clone();
    q.global_digest += Fr::ONE;
    cases.push(("made for another statement", key.clone(), honest.clone(), q));

    for (want, k, p, q) in cases {
        match refusal(&k, &q, &p) {
            VerifyError::Statement(why) => assert!(why.contains(want), "expected `{want}`: {why}"),
            other => panic!("expected Statement(`{want}`), got {other:?}"),
        }
    }
}

/// Step 6: a proof shaped wrong for its circuit, under the right digest, is
/// `Malformed` — never an index out of range.
#[test]
fn a_proof_shaped_wrong_is_refused_as_malformed() {
    let key = vk();
    let public = statement();
    let honest = shell(&key, &public);
    let mut cases: Vec<(&str, verifier_core::ShardProof)> = Vec::new();
    let mut q = honest.clone();
    q.family = ZERO;
    cases.push(("a shard the statement does not have", q));
    let mut q = honest.clone();
    q.shard_index = 1;
    cases.push(("a shard the statement does not have", q));
    let mut q = honest.clone();
    q.family = 3;
    cases.push(("a shard the statement does not have", q));
    let mut q = honest.clone();
    q.witness_commitments.pop();
    cases.push(("the witness commitments are not the circuit's width", q));
    let mut q = honest.clone();
    q.outputs.push(Fr::ZERO);
    cases.push(("the outputs are not the circuit's output map", q));
    cases.push(("a GKR transition is not its layer's shape", honest.clone()));
    let mut q = honest.clone();
    q.gkr.layers = vec![
        SumcheckProof {
            rounds: vec![],
            final_evals: vec![],
        };
        key.circuits[0].artifact.depth()
    ];
    cases.push(("a GKR transition is not its layer's shape", q));
    for (want, q) in cases {
        match refusal(&key, &q, &public) {
            VerifyError::Malformed(why) => assert!(why.contains(want), "expected `{want}`: {why}"),
            other => panic!("expected Malformed(`{want}`), got {other:?}"),
        }
    }
}

/// Garbage in the fields `reduce_shard` indexes by before the replay — the
/// statement's shard counts, windows and lists, and the proof's family, shard
/// index, outputs and witness commitments — two thousand ways: every one is
/// refused, and none panics. The shell carries no GKR transitions, so nothing
/// here reaches step 7; the proofs that do are the prover's suites.
#[test]
fn garbage_is_refused_and_never_panics() {
    let key = vk();
    let public = statement();
    let proof = shell(&key, &public);
    let mut seed = 0x5316u64;
    let mut next = || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        seed >> 33
    };
    for _ in 0..2000 {
        let (mut p, mut q) = (public.clone(), proof.clone());
        match next() % 8 {
            0 => p.shard_counts[(next() % 3) as usize] = next() as u32,
            1 => p.windows = (0..next() % 4).map(|_| next() as u32).collect(),
            2 => p.memory_commitments.truncate((next() % 3) as usize),
            3 => p.memory_roots.truncate((next() % 3) as usize),
            4 => q.family = (next() % 12) as u32,
            5 => q.shard_index = next() as u32,
            6 => q.outputs.truncate((next() % 9) as usize),
            _ => q.witness_commitments.truncate((next() % 34) as usize),
        }
        assert!(reduce_shard(&key, &q, &p).is_err());
    }
}

/// **Step 10b reads the statement and the key, and no `ShardProof` at all**,
/// `docs/spec/shard-proof.md` §6: it is `verify_global_memory`, and a block
/// runs it once however many shards it has. Its own three checks keep S16's
/// order — the boundary's range, then the exit status, then the product — so
/// a statement broken two ways answers with the first.
#[test]
fn the_statement_half_of_the_memory_argument_is_one_check_for_a_statement() {
    let key = vk();
    let answer = |edit: fn(&mut verifier_core::PublicInputs)| {
        let mut p = statement();
        edit(&mut p);
        // Every edit but the roots and the exit status moves the digest, so
        // each statement is judged against challenges of its own.
        let g = derive_global_phase(&key, &p).expect("a statement the key describes");
        verify_global_memory(&key, &g, &p)
    };
    let memory = VerifyError::MemoryArgument;
    let late = memory("a boundary timestamp is not below 2^38");
    assert_eq!(answer(|p| p.boundary.reg_ts[5] = 1 << 38), Err(late));
    assert_eq!(answer(|p| p.boundary.pc_ts = 1 << 38), Err(late));
    assert_eq!(
        answer(|p| p.exit_status += 1),
        Err(memory("x10's final value is not the exit status"))
    );
    // Both, and the range refusal is the one returned: 10b's internal order
    // is S16's step 10, which checked the range first.
    assert_eq!(
        answer(|p| {
            p.boundary.pc_ts = 1 << 38;
            p.exit_status += 1;
        }),
        Err(late)
    );
    // The synthetic roots are 1, 2, 3 and 4, which no boundary reconciles.
    assert_eq!(
        answer(|_| ()),
        Err(memory("the statement's roots do not reconcile"))
    );
    // And the product is what refuses them: the roots move it, though they
    // move no challenge — the digest test above pins that they do not.
    let mut p = statement();
    p.memory_roots[0][0] += Fr::ONE;
    let g = derive_global_phase(&key, &p).expect("a statement the key describes");
    assert_eq!(
        verify_global_memory(&key, &g, &p),
        Err(memory("the statement's roots do not reconcile"))
    );
}
