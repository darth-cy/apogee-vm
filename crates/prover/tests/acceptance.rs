//! S16's acceptance over the real statement: `guests/addsub`, proved and
//! verified shard by shard.
//!
//! **Every test here is `#[ignore]`d, and runs by name with
//! `--include-ignored --test-threads=1`** — the execution family's shard is
//! `2^20` rows, the timestamp channel's floor, and one statement's proof peaks
//! at about 8.6 GB, so two at once do not fit a runner. Master rule 7: the
//! stage's PR runs it locally, and `.github/workflows/ci.yml` carries the
//! command under `# DEFERRED:`. What needs no proof — the wire forms, the key's
//! load rules, the statement's refusals, the circuit row by row — is in
//! `crates/verifier-core/tests` and `crates/checker/tests/add_sub.rs`, and runs
//! in ordinary CI.

mod common;

use constants::{family, transcript_tags as tags};
use program::ProgramIdentity;
use prover::{
    advance, finish, global_commit_phase, prove_shard, prove_shard_columns, public_inputs,
    shard_columns, statement_inputs, ProverSetup, ProvingContext,
};
use trace::{Phase, TraceArchive};
use transcript::TranscriptEvent::{self, Absorb, Challenge};
use verifier::{load_verifying_key, verify_shard, PublicInputs, ShardProof, VerifyError};
use verifier_core::{global_commit, reduce_shard, statement_shards};

const ADD: u32 = family::ADD_SUB_LUI_AUIPC;
const INIT: u32 = family::INIT_TEARDOWN;

/// The whole statement, proved through `advance`: the setup, the filled
/// archive, and what its final phase holds.
fn proved() -> (ProverSetup, TraceArchive, PublicInputs, Vec<ShardProof>) {
    let setup = common::setup();
    let mut archive = common::archive(&setup.program);
    advance(&setup, &mut archive, Phase::Final).expect("the statement proves");
    let (public, proofs) = finish(&archive).expect("the final phase decodes");
    (setup, archive, public, proofs)
}

/// The byte length a proof of `artifact` has: §9's layout, every count read
/// off the circuit.
fn proof_bytes(a: &constraints::CircuitArtifact) -> usize {
    let transitions: usize = (0..a.depth())
        .map(|k| {
            let claims = a.layer_width(k) as usize * if a.layers[k].halving { 2 } else { 1 };
            4 + 128 * a.layer_vars(k + 1) as usize + 4 + 32 * claims
        })
        .sum();
    4 + 4
        + 16
        + 32
        + (4 + 64 * a.witness.len())
        + (4 + 32 * a.outputs.len())
        + 4
        + transitions
        + 704
}

// ---------------------------------------------------------------------------
// Acceptance 1
// ---------------------------------------------------------------------------

/// Acceptance 1. The tiny guest decodes into exactly the add/sub family and the
/// two RAM window families, every pc claimed by the first; its trace
/// self-checks; `advance` proves one `INIT_TEARDOWN` shard and one
/// `ADD_SUB_LUI_AUIPC` shard; `verify_shard` accepts both against one
/// statement; and every proof has its circuit's shape — its round counts, its
/// claim counts, and a byte length that is a function of the key and the family
/// alone. (Its QEMU differential is `crates/emulator/tests/differential.rs`'s,
/// where `addsub` is in the suite.)
#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 8.6 GB"]
fn a1_the_tiny_guest_proves_and_both_shards_verify() {
    let (setup, archive, public, proofs) = proved();
    let config = &setup.program.config;
    assert_eq!(
        config.families,
        vec![
            (ADD, 1 << 20),
            (INIT, 1 << 16),
            (family::ZERO_WINDOWS, 1 << 16)
        ]
    );
    let table = setup.program.tables.family(ADD).expect("the add/sub table");
    let live = (0..table.height as usize)
        .filter(|r| table.is_live(*r))
        .count();
    assert_eq!(live, 29, "every instruction of addsub is the family's");
    assert_eq!(
        archive.memory_log().self_check(&setup.program.image),
        Ok(())
    );
    assert_eq!(
        archive.cycle_profile().counts,
        vec![(ADD, 29), (INIT, 0), (family::ZERO_WINDOWS, 0)]
    );

    assert_eq!(public.shard_counts, vec![1, 1, 0]);
    assert!(public.windows.is_empty(), "addsub touches no RAM");
    assert_eq!(public.exit_status, common::RESULT);
    assert!(public.input.is_empty() && public.output.is_empty());
    let shards: Vec<(u32, u32)> = proofs.iter().map(|p| (p.family, p.shard_index)).collect();
    assert_eq!(shards, vec![(INIT, 0), (ADD, 0)]);

    for proof in &proofs {
        assert_eq!(verify_shard(&setup.vk, proof, &public), Ok(()));
        let circuit = setup.vk.circuit(proof.family).expect("a circuit");
        let a = &circuit.artifact;
        assert_eq!(
            proof.gkr.layers.len(),
            a.depth(),
            "one transition per gate list"
        );
        for (k, layer) in proof.gkr.layers.iter().enumerate() {
            assert_eq!(
                layer.rounds.len(),
                a.layer_vars(k + 1) as usize,
                "transition {k}"
            );
            let claims = a.layer_width(k) as usize * if a.layers[k].halving { 2 } else { 1 };
            assert_eq!(layer.final_evals.len(), claims, "transition {k}");
        }
        assert_eq!(proof.gkr.layers[0].final_evals.len(), a.committed().len());
        assert_eq!(proof.witness_commitments.len(), a.witness.len());
        assert_eq!(proof.outputs.len(), 2 + 2 * circuit.channels.len());
        assert_eq!(proof.to_bytes().len(), proof_bytes(a));
    }
    let [init, add] = [&proofs[0], &proofs[1]];
    assert_eq!(add.to_bytes().len(), 57_100);
    assert_eq!(init.to_bytes().len(), 20_524);
    assert_eq!(add.gkr.layers.len(), 25);
    assert_eq!(add.gkr.layers[0].rounds.len(), 20);
    assert_eq!(add.gkr.layers[0].final_evals.len(), 36 + 31 + 7);
}

// ---------------------------------------------------------------------------
// Acceptance 5
// ---------------------------------------------------------------------------

fn statement_refusal(result: Result<(), VerifyError>, what: &str) {
    assert!(
        matches!(result, Err(VerifyError::Statement(_))),
        "{what}: expected a Statement refusal, got {result:?}"
    );
}

/// Acceptance 5. The honest proofs, checked against a statement they were not
/// made for: another program identity, another public I/O digest, another
/// static `VmConfig`, other shard counts, another SRS digest, one memory
/// commitment swapped, and other public inputs altogether — each refused as
/// `Statement`, for every shard.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 8.6 GB"]
fn a5_every_statement_twin_is_refused_as_statement() {
    let (setup, _, public, proofs) = proved();
    let vk = &setup.vk;
    for proof in &proofs {
        let mut k = vk.clone();
        k.identity = ProgramIdentity(k.identity.0 + field::Fr::ONE);
        statement_refusal(verify_shard(&k, proof, &public), "identity");

        let mut p = public.clone();
        p.output = vec![42];
        statement_refusal(verify_shard(vk, proof, &p), "the public I/O digest");

        let mut k = vk.clone();
        k.config.bytecode_size_words += 1;
        statement_refusal(verify_shard(&k, proof, &public), "the static VmConfig");
        let mut k = vk.clone();
        k.config.families[0].1 = 1 << 22;
        statement_refusal(verify_shard(&k, proof, &public), "a static height");

        let mut p = public.clone();
        p.shard_counts[0] = 2;
        statement_refusal(verify_shard(vk, proof, &p), "the add/sub shard count");
        let mut p = public.clone();
        p.shard_counts[2] = 1;
        p.windows = vec![1];
        p.memory_commitments
            .insert(1, p.memory_commitments[0].clone());
        p.memory_roots.insert(1, p.memory_roots[0]);
        statement_refusal(verify_shard(vk, proof, &p), "a zero-window shard added");

        let mut k = vk.clone();
        k.srs_digest += field::Fr::ONE;
        statement_refusal(verify_shard(&k, proof, &public), "the SRS digest");

        let mut p = public.clone();
        p.memory_commitments[1].swap(0, 1);
        statement_refusal(
            verify_shard(vk, proof, &p),
            "two memory commitments swapped",
        );
        let mut p = public.clone();
        p.memory_commitments[0][0] = p.memory_commitments[1][0];
        statement_refusal(verify_shard(vk, proof, &p), "a memory commitment replaced");

        let mut p = public.clone();
        p.input = vec![0, 0, 0, 0];
        statement_refusal(verify_shard(vk, proof, &p), "other public inputs");
    }
}

/// Step 10's first check is the one link between the roots a shard's proof
/// establishes and the roots reconciliation multiplies: the statement's roots
/// are not absorbed. A statement whose init shard's root pair is scaled by one
/// constant still reconciles, so that shard's proof is what refuses it — while
/// the add/sub shard, whose own roots are untouched, accepts it. That is why a
/// statement is verified only when every one of its shards is.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 8.6 GB"]
fn a_statement_root_that_is_not_its_proofs_is_refused_by_that_shard() {
    let (setup, _, public, proofs) = proved();
    assert_eq!((proofs[0].family, proofs[1].family), (INIT, ADD));
    let seven = field::Fr::from_u64(7);
    let mut forged = public.clone();
    let [read, write] = forged.memory_roots[0];
    forged.memory_roots[0] = [read * seven, write * seven];
    assert_eq!(
        verify_shard(&setup.vk, &proofs[0], &forged),
        Err(VerifyError::MemoryArgument(
            "the shard's roots are not the statement's"
        ))
    );
    assert_eq!(verify_shard(&setup.vk, &proofs[1], &forged), Ok(()));
}

// ---------------------------------------------------------------------------
// Acceptance 6 and 8
// ---------------------------------------------------------------------------

/// Acceptance 8's walker, S13's: a batch or child challenge is drawn only after
/// every claim it reduces is absorbed, and after each reduction exactly one
/// point is outstanding. Returns the index of the last GKR event.
fn one_claim_after_each_batch(a: &constraints::CircuitArtifact, log: &[TranscriptEvent]) -> usize {
    let depth = a.depth();
    let (mut outstanding, mut batches, mut last) = (0usize, 0usize, 0usize);
    let mut previous: Option<TranscriptEvent> = None;
    for (i, event) in log.iter().enumerate() {
        match *event {
            Challenge {
                tag: tags::GKR_OUTPUT_POINT,
            } => outstanding = 1,
            Absorb {
                tag: tags::GKR_OUTPUTS,
                ..
            } => outstanding = 1,
            Challenge {
                tag: tags::GKR_BATCH,
            } => {
                assert_eq!(outstanding, 1, "a batch reduces one outstanding point");
                assert!(matches!(
                    previous,
                    Some(Absorb {
                        tag: tags::GKR_LAYER_CLAIMS,
                        ..
                    }) | Some(Absorb {
                        tag: tags::GKR_OUTPUTS,
                        ..
                    }) | Some(Challenge {
                        tag: tags::GKR_OUTPUT_POINT
                    }) | Some(Challenge {
                        tag: tags::GKR_CHILD
                    })
                ));
                outstanding = 0;
                batches += 1;
            }
            Absorb {
                tag: tags::GKR_LAYER_CLAIMS,
                n_scalars,
            } => {
                let k = depth - batches;
                let points = if a.layers[k].halving { 2 } else { 1 };
                assert_eq!(outstanding, 0);
                assert_eq!(n_scalars, points * a.layer_width(k) as usize);
                outstanding = points;
                last = i;
            }
            Challenge {
                tag: tags::GKR_CHILD,
            } => {
                assert_eq!(outstanding, 2, "the child challenge follows both children");
                outstanding = 1;
                last = i;
            }
            _ => {}
        }
        previous = Some(*event);
    }
    assert_eq!(batches, depth, "one batch per transition");
    assert_eq!(outstanding, 1, "the base claims sit at one point");
    last
}

/// The GKR engine's transcript events over `a`, as `docs/spec/gkr.md` §5.2
/// writes them, from the artifact's shape alone.
fn gkr_schedule(a: &constraints::CircuitArtifact) -> Vec<TranscriptEvent> {
    let depth = a.depth();
    let mut events = vec![Absorb {
        tag: tags::GKR_OUTPUTS,
        n_scalars: a.outputs.len() << a.layer_vars(depth),
    }];
    for _ in 0..a.layer_vars(depth) {
        events.push(Challenge {
            tag: tags::GKR_OUTPUT_POINT,
        });
    }
    for k in (0..depth).rev() {
        events.push(Challenge {
            tag: tags::GKR_BATCH,
        });
        for _ in 0..a.layer_vars(k + 1) {
            events.push(Absorb {
                tag: tags::SUMCHECK_ROUND,
                n_scalars: 4,
            });
            events.push(Challenge {
                tag: tags::SUMCHECK_CHALLENGE,
            });
        }
        let halving = a.layers[k].halving;
        events.push(Absorb {
            tag: tags::GKR_LAYER_CLAIMS,
            n_scalars: a.layer_width(k) as usize * if halving { 2 } else { 1 },
        });
        if halving {
            events.push(Challenge {
                tag: tags::GKR_CHILD,
            });
        }
    }
    events
}

/// Acceptance 6 and 8, on the add/sub shard's real transcript: the seed, the
/// window and the witness commitments first; `g` and `β` after every
/// commitment; the GKR schedule with at most one outstanding point after each
/// batch, top to bottom; then the one batched opening, whose column-RLC
/// challenge follows every evaluation claim it combines. The proof holds one
/// Mercury proof, every base claim is at one point — the prover asserts it, and
/// the verifier's reduction re-derives the same point — and the global
/// transcript draws its memory challenges after every memory commitment.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 8.6 GB"]
fn a6_a8_one_opening_at_one_point_and_every_challenge_after_what_it_protects() {
    let setup = common::setup();
    let archive = common::archive(&setup.program);
    let inputs = statement_inputs(&setup, &archive).unwrap();
    let global = global_commit_phase(&setup.vk, &setup.srs, &inputs);
    let ctx = ProvingContext {
        setup: &setup,
        global: global.clone(),
    };

    // The global transcript: every memory commitment, the boundary, then the
    // four challenges and the digest, and nothing drawn before.
    let g = global_commit(&setup.vk, &global.statement);
    let log = g.transcript.event_log();
    let first_challenge = log
        .iter()
        .position(|e| matches!(e, Challenge { .. }))
        .unwrap();
    let last_commitment = log
        .iter()
        .rposition(|e| {
            matches!(
                e,
                Absorb {
                    tag: tags::COMMITMENT,
                    ..
                }
            )
        })
        .unwrap();
    assert!(last_commitment < first_challenge);
    assert_eq!(
        log[first_challenge - 1],
        Absorb {
            tag: tags::MEMORY_BOUNDARY,
            n_scalars: 64
        }
    );
    assert_eq!(g.digest, global.digest);

    let mut proofs = Vec::new();
    for (family, index) in statement_shards(&setup.vk.config, &inputs.shard_counts) {
        let columns = shard_columns(&setup, &archive, family, index, &inputs.windows).unwrap();
        let (proof, log) = prove_shard_columns(&ctx, family, index, columns);
        let a = &setup.vk.circuit(family).unwrap().artifact;

        assert_eq!(
            log[..5],
            [
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
                    n_scalars: 4 * a.witness.len()
                },
                Challenge {
                    tag: tags::LOOKUP_CHALLENGE
                },
                Challenge {
                    tag: tags::LOOKUP_CHALLENGE
                },
            ]
        );
        assert_eq!(
            log[5],
            Absorb {
                tag: tags::GKR_OUTPUTS,
                n_scalars: a.outputs.len()
            }
        );
        let last_gkr = one_claim_after_each_batch(a, &log);
        // And the schedule event for event, `docs/spec/gkr.md` §5.2: the
        // outputs and the top point, then per transition from the top the
        // batch, every round's cubic and challenge, the claims, and a halving
        // transition's child challenge.
        assert_eq!(log[5..=last_gkr], gkr_schedule(a)[..], "the GKR schedule");
        // Every GKR challenge — the batches, the rounds, the children — after
        // every commitment the shard reads.
        let first_gkr_challenge = log
            .iter()
            .position(|e| matches!(e, Challenge { tag } if *tag != tags::LOOKUP_CHALLENGE))
            .unwrap();
        assert!(first_gkr_challenge > 2);

        // The opening: B1, B2, B3, then S08's sixteen steps, once.
        let k = a.committed().len();
        let tail = &log[last_gkr + 1..];
        assert_eq!(
            tail[..3],
            [
                Absorb {
                    tag: tags::COMMITMENT,
                    n_scalars: 4 * k
                },
                Absorb {
                    tag: tags::EVALUATION_CLAIM,
                    n_scalars: a.trace_vars as usize + k
                },
                Challenge {
                    tag: tags::MERCURY_BATCH
                },
            ]
        );
        let batch = last_gkr + 3;
        // Every claim message — one per transition, then the opening's — is
        // absorbed before the column-RLC challenge.
        assert_eq!(
            log[..batch]
                .iter()
                .filter(|e| matches!(
                    e,
                    Absorb {
                        tag: tags::GKR_LAYER_CLAIMS | tags::EVALUATION_CLAIM,
                        ..
                    }
                ))
                .count(),
            a.depth() + 1
        );
        assert_eq!(
            log[batch..]
                .iter()
                .filter(|e| **e
                    == Challenge {
                        tag: tags::MERCURY_BATCH
                    })
                .count(),
            1,
            "one column-RLC challenge"
        );
        assert_eq!(
            log.iter()
                .filter(|e| **e
                    == Challenge {
                        tag: tags::PAIRING_MERGE
                    })
                .count(),
            1,
            "one Mercury opening"
        );
        assert_eq!(
            *log.last().unwrap(),
            Challenge {
                tag: tags::PAIRING_MERGE
            }
        );
        assert!(pcs::MercuryProof::from_bytes(&proof.opening).is_some());
        proofs.push(proof);
    }

    // The verifier re-derives the one point the prover opened at.
    let public = public_inputs(&global, &proofs);
    for proof in &proofs {
        let claim = reduce_shard(&setup.vk, proof, &public).expect("the honest shard reduces");
        let a = &setup.vk.circuit(proof.family).unwrap().artifact;
        assert_eq!(claim.point.len(), a.trace_vars as usize);
        assert_eq!(claim.values, proof.gkr.layers[0].final_evals);
        assert_eq!(claim.commitments.len(), a.committed().len());
        assert_eq!(verify_shard(&setup.vk, proof, &public), Ok(()));
    }
    // And `prove_shard`, the frozen entry point, is these same steps.
    let again = prove_shard(&ctx, &archive, ADD, 0);
    assert_eq!(again, proofs[1]);
}

// ---------------------------------------------------------------------------
// Acceptance 9
// ---------------------------------------------------------------------------

fn exported(archive: &TraceArchive) -> TraceArchive {
    let mut bytes = Vec::new();
    archive.export(&mut bytes).expect("exporting");
    TraceArchive::import(&bytes[..]).expect("importing")
}

/// Acceptance 9. Interrupted after post-execution, after post-commit, after
/// post-GKR and after post-opening, exported, imported and resumed, the statement finishes to the
/// same bytes as the uninterrupted run: every phase's content, and so every
/// proof. Each phase is timed, and the timing is outside the deterministic
/// payload.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 8.6 GB"]
fn a9_a_resumed_statement_is_byte_identical() {
    let (setup, whole, _, _) = proved();
    // Stopping at post-execution fills nothing: the archive is as the
    // emulator left it.
    for stop in [
        Phase::PostExecution,
        Phase::PostCommit,
        Phase::PostGkr,
        Phase::PostOpening,
    ] {
        let mut part = common::archive(&setup.program);
        advance(&setup, &mut part, stop).expect("the first half");
        for later in [
            Phase::PostCommit,
            Phase::PostGkr,
            Phase::PostOpening,
            Phase::Final,
        ] {
            assert_eq!(part.is_filled(later), later <= stop, "{stop:?}: {later:?}");
            assert_eq!(part.timing(later).is_some(), later <= stop);
        }
        let mut resumed = exported(&part);
        advance(&setup, &mut resumed, Phase::Final).expect("the second half");
        for phase in [
            Phase::PostCommit,
            Phase::PostGkr,
            Phase::PostOpening,
            Phase::Final,
        ] {
            assert_eq!(
                resumed.content(phase),
                whole.content(phase),
                "{stop:?}: {phase:?}"
            );
        }
        assert_eq!(
            resumed.deterministic_payload(),
            whole.deterministic_payload()
        );
        assert_eq!(finish(&resumed).unwrap(), finish(&whole).unwrap());
    }
    // A finished archive advanced again changes nothing.
    let mut again = exported(&whole);
    advance(&setup, &mut again, Phase::Final).unwrap();
    assert_eq!(again.deterministic_payload(), whole.deterministic_payload());
}

// ---------------------------------------------------------------------------
// Serde, the key's load, determinism
// ---------------------------------------------------------------------------

/// Acceptance 10's library half: every proof, the statement and the key
/// round-trip byte for byte in their canonical encodings, and the key loads
/// through `load_verifying_key` — the core's load rules and every curve point
/// — back to itself. The CLI half is `crates/verifier/tests/cli.rs`.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 8.6 GB"]
fn a10_the_proofs_the_statement_and_the_key_round_trip() {
    let (setup, _, public, proofs) = proved();
    for proof in &proofs {
        let bytes = proof.to_bytes();
        let back = ShardProof::from_bytes(&bytes).unwrap();
        assert_eq!(&back, proof);
        assert_eq!(back.to_bytes(), bytes);
        assert_eq!(verify_shard(&setup.vk, &back, &public), Ok(()));
    }
    let bytes = public.to_bytes();
    assert_eq!(PublicInputs::from_bytes(&bytes).unwrap().to_bytes(), bytes);
    let bytes = setup.vk.to_bytes();
    let loaded = load_verifying_key(&bytes).expect("the key loads");
    assert_eq!(loaded, setup.vk);
    assert_eq!(loaded.to_bytes(), bytes);
}

/// Proofs do not depend on the thread count: the statement proved on one
/// thread is byte for byte the statement proved on every core.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 8.6 GB"]
fn the_proofs_do_not_depend_on_the_thread_count() {
    let (setup, whole, _, _) = proved();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .expect("a one-thread pool");
    let serial = pool.install(|| {
        let mut archive = common::archive(&setup.program);
        advance(&setup, &mut archive, Phase::Final).unwrap();
        archive
    });
    assert_eq!(
        serial.deterministic_payload(),
        whole.deterministic_payload()
    );
}
