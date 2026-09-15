//! The memory artifacts under the checker: `memory_roots`, the root self-check
//! hook of `docs/spec/memory.md` §1, agrees with a forwarded window and fails
//! when a row under a root changes; and the three artifacts keep the laws, the
//! lookup rules and the padding contract, the frame its product-tree clause.

use checker::{check_laws, check_padding, check_padding_identity, memory_roots};
use constants::challenge_slot::{MEM_ALPHA_VAL, MEM_GAMMA};
use constraints::memory::{frame_artifact, image_window_artifact, zero_window_artifact};
use constraints::CircuitArtifact;
use field::Fr;
use gkr::{forward, window_challenges, BaseLayer, ExternalChallenges, LayerValues};
use poly::{MultilinearPoly, PolyBacking};
use test_support::Rng;

/// A forwarded artifact over random columns and random slots 1–4, plus slot 5
/// for window 9.
fn forwarded(a: &CircuitArtifact, seed: u64) -> LayerValues {
    let mut rng = Rng::new(seed);
    let rows = 1usize << a.trace_vars;
    let mut memory = ExternalChallenges::new();
    for slot in MEM_GAMMA..=MEM_ALPHA_VAL {
        memory.insert(slot, Fr::from_u64(rng.next_u64()));
    }
    let columns = a
        .committed()
        .into_iter()
        .map(|address| {
            let column = (0..rows).map(|_| Fr::from_u64(rng.next_u64())).collect();
            (address, MultilinearPoly::new(PolyBacking::Fr(column)))
        })
        .collect();
    let challenges = window_challenges(&memory, 9, a.trace_vars);
    forward(a, &BaseLayer::new(columns), &challenges)
}

type Constructor = fn(u32) -> CircuitArtifact;

/// Each artifact at `trace_vars` 4 beside the layer its first halving list
/// reads: layer 1 for a window, whose leaves it halves at once, and layer 4
/// for the frame, above its three row-wise lists.
const HALVING_INPUTS: [(&str, Constructor, usize); 2] = [
    ("zero window", zero_window_artifact, 1),
    ("frame", frame_artifact, 4),
];

/// On a forwarded artifact the roots are the top's two values and the
/// products of layer `k`'s columns 0 and 1, written out here. Kills a hook
/// that reads any layer but the first halving list's input.
#[test]
fn memory_roots_agrees_with_a_forwarded_artifact() {
    for (label, construct, k) in HALVING_INPUTS {
        let a = construct(4);
        let values = forwarded(&a, 0x5714_3201);
        let top = values.layers.last().expect("a top layer");
        let product =
            |j: usize| (0..16).fold(Fr::ONE, |acc, y| acc * values.layers[k - 1][j].get(y));
        assert_eq!(
            memory_roots(&a, &values),
            Ok((top[0].get(0), top[1].get(0))),
            "{label}"
        );
        assert_eq!(
            memory_roots(&a, &values),
            Ok((product(0), product(1))),
            "{label}"
        );
    }
}

/// One row under a root changed in `LayerValues`, the top left as it was:
/// refused. The same for the write side, on both artifacts. Kills a hook that
/// reads the roots off the top without recomputing them.
#[test]
fn memory_roots_refuses_a_changed_row_under_a_root() {
    for (label, construct, k) in HALVING_INPUTS {
        let a = construct(4);
        for j in 0..2 {
            let mut values = forwarded(&a, 0x5714_3202);
            let column = &values.layers[k - 1][j];
            let mut rows: Vec<Fr> = (0..column.len()).map(|y| column.get(y)).collect();
            rows[3] += Fr::ONE;
            values.layers[k - 1][j] = MultilinearPoly::new(PolyBacking::Fr(rows));
            let e = memory_roots(&a, &values).unwrap_err();
            assert!(
                e.contains(&format!("layer {k}'s column {j}")),
                "{label}: {e}"
            );
        }
    }
}

/// The halving input replaced by one-row columns holding the roots themselves,
/// whose products are the top: refused by height. A layer list of the wrong
/// depth is refused too. Kills a hook that takes the column heights from
/// `values` rather than from the artifact.
#[test]
fn memory_roots_refuses_a_layer_of_the_wrong_height_or_depth() {
    let a = zero_window_artifact(4);
    let mut values = forwarded(&a, 0x5714_3204);
    let top: Vec<Fr> = values
        .layers
        .last()
        .expect("a top")
        .iter()
        .map(|c| c.get(0))
        .collect();
    values.layers[0] = top
        .iter()
        .map(|root| MultilinearPoly::new(PolyBacking::Fr(vec![*root])))
        .collect();
    assert_eq!(
        memory_roots(&a, &values),
        Err("memory roots: layer 1's column 0 has 1 rows, not 16".to_string())
    );

    let mut values = forwarded(&a, 0x5714_3204);
    values.layers.remove(1);
    assert_eq!(
        memory_roots(&a, &values),
        Err("memory roots: 4 layers are materialized, and the artifact has 5".to_string())
    );
}

#[test]
fn memory_roots_refuses_an_artifact_with_no_halving_list() {
    let a = zero_window_artifact(4);
    let values = forwarded(&a, 0x5714_3203);
    let mut row_wise = a.clone();
    row_wise.layers.truncate(1);
    assert_eq!(
        memory_roots(&row_wise, &values),
        Err("memory roots: the artifact has no halving list".to_string())
    );
}

/// The checker's own laws, lookup rules and padding contract hold on all three
/// constructors — the `zero_row_valid` each computes included — and the
/// frame, an execution family's subtree whose shards have inactive rows, keeps
/// the product-tree clause.
#[test]
fn the_memory_artifacts_keep_the_laws_and_the_padding_contract() {
    for (label, a) in [
        ("frame", frame_artifact(6)),
        ("image window", image_window_artifact(6)),
        ("zero window", zero_window_artifact(6)),
    ] {
        assert_eq!(check_laws(&a), Ok(()), "{label}");
        assert_eq!(check_padding(&a), Ok(()), "{label}");
    }
    assert_eq!(check_padding_identity(&frame_artifact(6)), Ok(()));
}
