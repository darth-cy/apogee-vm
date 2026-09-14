//! Acceptance 4: the batched-claim invariant of must-be-exact 6, over the whole
//! backward pass, read off the transcript's event log — and the log itself,
//! event for event, against the frozen schedule of `docs/spec/gkr.md` §5.2.

mod common;

use common::{bind, output_claims, toy, toy_base, toy_columns};
use constants::transcript_tags as tags;
use constraints::CircuitArtifact;
use gkr::{forward, prove, verify};
use transcript::TranscriptEvent::{self, Absorb, Challenge};

/// The toy's schedule written out: after the binding and the external
/// challenge, the outputs (two tables of 8), the 3-coordinate point, then the
/// halving transition (3 rounds, 4 child claims, the child challenge), then two
/// row-wise transitions of 4 rounds each, leaving 3 and then 6 claims.
fn expected_log() -> Vec<TranscriptEvent> {
    let mut log = vec![
        Absorb {
            tag: tags::WITNESS_DIGEST,
            n_scalars: 1,
        },
        Challenge {
            tag: tags::SUMCHECK_CHALLENGE,
        },
        Absorb {
            tag: tags::GKR_OUTPUTS,
            n_scalars: 16,
        },
    ];
    log.extend(
        [Challenge {
            tag: tags::GKR_OUTPUT_POINT,
        }; 3],
    );
    let transition = |log: &mut Vec<TranscriptEvent>, rounds: usize, claims: usize| {
        log.push(Challenge {
            tag: tags::GKR_BATCH,
        });
        for _ in 0..rounds {
            log.push(Absorb {
                tag: tags::SUMCHECK_ROUND,
                n_scalars: 4,
            });
            log.push(Challenge {
                tag: tags::SUMCHECK_CHALLENGE,
            });
        }
        log.push(Absorb {
            tag: tags::GKR_LAYER_CLAIMS,
            n_scalars: claims,
        });
    };
    transition(&mut log, 3, 4);
    log.push(Challenge {
        tag: tags::GKR_CHILD,
    });
    transition(&mut log, 4, 3);
    transition(&mut log, 4, 6);
    log
}

/// Walk a log and hold must-be-exact 6 at every step: a batch or child
/// challenge is drawn only once every claim it reduces has been absorbed, and
/// after each reduction exactly one claim point is outstanding. Which
/// transitions halve, and how many claims each leaves, are read from
/// `artifact`, never guessed from the log. Returns how many batches and child
/// reductions it saw.
///
/// The exact equality with `expected_log` is the implementation check: it is
/// what fails when `prove` or `verify` drifts from the schedule. This walker
/// checks the schedule's own invariant, on whatever log it is handed.
fn outstanding_claims_never_exceed_one(
    artifact: &CircuitArtifact,
    log: &[TranscriptEvent],
) -> (usize, usize) {
    let depth = artifact.depth();
    // Points awaiting reduction: none until the outputs' point exists.
    let mut outstanding = 0usize;
    let mut previous: Option<TranscriptEvent> = None;
    let (mut batches, mut children) = (0, 0);
    for event in log {
        match *event {
            Challenge {
                tag: tags::GKR_OUTPUT_POINT,
            } => outstanding = 1,
            Challenge {
                tag: tags::GKR_BATCH,
            } => {
                assert!(batches < depth, "one batch per transition");
                assert_eq!(
                    outstanding, 1,
                    "a batch reduces exactly one outstanding point"
                );
                let last_absorb = matches!(
                    previous,
                    Some(Absorb {
                        tag: tags::GKR_LAYER_CLAIMS,
                        ..
                    }) | Some(Challenge {
                        tag: tags::GKR_OUTPUT_POINT
                    }) | Some(Challenge {
                        tag: tags::GKR_CHILD
                    })
                );
                assert!(last_absorb, "a batch follows the claims it batches");
                outstanding = 0;
                batches += 1;
            }
            Absorb {
                tag: tags::GKR_LAYER_CLAIMS,
                n_scalars,
            } => {
                assert_eq!(outstanding, 0, "claims come out of a sumcheck");
                assert!(batches >= 1, "claims come out of a batched transition");
                // Batches run from transition depth − 1 down to 0.
                let k = depth - batches;
                // A halving transition leaves two points, (ρ, 0) and (ρ, 1).
                let points = if artifact.layers[k].halving { 2 } else { 1 };
                assert_eq!(
                    n_scalars,
                    points * artifact.layer_width(k) as usize,
                    "transition {k} leaves one claim per column at each point"
                );
                outstanding = points;
            }
            Challenge {
                tag: tags::GKR_CHILD,
            } => {
                assert_eq!(outstanding, 2, "the child challenge follows both children");
                assert!(
                    matches!(
                        previous,
                        Some(Absorb {
                            tag: tags::GKR_LAYER_CLAIMS,
                            ..
                        })
                    ),
                    "both child claims are absorbed immediately before the child challenge"
                );
                outstanding = 1;
                children += 1;
            }
            _ => {}
        }
        previous = Some(*event);
    }
    assert_eq!(outstanding, 1, "the base claims sit at one point");
    (batches, children)
}

#[test]
fn every_reduction_follows_the_claims_it_reduces() {
    let artifact = toy();
    let base = toy_base(&toy_columns(0x5313_0900));
    let (mut prover, challenges) = bind(&artifact, &base);
    let values = forward(&artifact, &base, &challenges);
    let proof = prove(&artifact, &values, &challenges, &mut prover);
    let (mut verifier, challenges) = bind(&artifact, &base);
    verify(
        &artifact,
        &proof,
        &output_claims(&artifact, &values),
        &challenges,
        &mut verifier,
    )
    .expect("the honest run verifies");

    assert_eq!(
        prover.event_log(),
        expected_log().as_slice(),
        "the prover's schedule"
    );
    assert_eq!(
        verifier.event_log(),
        expected_log().as_slice(),
        "the verifier's schedule"
    );
    assert_eq!(
        prover.snapshot(),
        verifier.snapshot(),
        "both sides end in one sponge state"
    );
    assert_eq!(
        outstanding_claims_never_exceed_one(&artifact, verifier.event_log()),
        (3, 1),
        "one batch per transition, one child reduction for the halving list"
    );
}

/// The walker can fail: a log whose child challenge precedes its claims, and
/// one that batches before any claim exists, are both caught.
#[test]
fn the_walker_rejects_a_reduction_before_its_claims() {
    let artifact = toy();
    assert_eq!(
        outstanding_claims_never_exceed_one(&artifact, &expected_log()),
        (3, 1),
        "the control walks"
    );
    let mut early_child = expected_log();
    let claims = early_child
        .iter()
        .position(|e| {
            matches!(
                e,
                Absorb {
                    tag: tags::GKR_LAYER_CLAIMS,
                    n_scalars: 4
                }
            )
        })
        .unwrap();
    early_child.swap(claims, claims + 1);
    assert!(
        std::panic::catch_unwind(|| outstanding_claims_never_exceed_one(&artifact, &early_child))
            .is_err()
    );

    let mut early_batch = expected_log();
    let point = early_batch
        .iter()
        .position(|e| {
            matches!(
                e,
                Challenge {
                    tag: tags::GKR_OUTPUT_POINT
                }
            )
        })
        .unwrap();
    early_batch.insert(
        point,
        Challenge {
            tag: tags::GKR_BATCH,
        },
    );
    assert!(
        std::panic::catch_unwind(|| outstanding_claims_never_exceed_one(&artifact, &early_batch))
            .is_err()
    );
}
