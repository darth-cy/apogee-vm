//! Acceptance 9: `plan_shards` at its edges.

use constants::family;
use program::VmConfig;
use trace::{plan_shards, CycleProfile, ShardPlan};

fn config(height: u32) -> VmConfig {
    VmConfig {
        families: vec![
            (family::ADD_SUB_LUI_AUIPC, height),
            (family::JUMP_BRANCH_SLT, 1 << 18),
            (family::INIT_TEARDOWN, 1 << 20),
        ],
        bytecode_size_words: family::DEFAULT_BYTECODE_SIZE_WORDS,
    }
}

fn profile(occupancy: u64) -> CycleProfile {
    CycleProfile {
        counts: vec![
            (family::ADD_SUB_LUI_AUIPC, occupancy),
            (family::JUMP_BRANCH_SLT, 0),
            (family::INIT_TEARDOWN, 0),
        ],
    }
}

/// Occupancy 0, 1, exactly the height and one past it: 0, 1, 1 and 2
/// shards, at every height on the menu — and the families that never ran
/// plan zero.
#[test]
fn shard_counts_at_the_edges() {
    for height in family::HEIGHT_MENU {
        let h = height as u64;
        for (occupancy, want) in [(0, 0), (1, 1), (h, 1), (h + 1, 2), (3 * h + 1, 4)] {
            let plan = plan_shards(&profile(occupancy), &config(height));
            assert_eq!(
                plan,
                ShardPlan {
                    shards: vec![
                        (family::ADD_SUB_LUI_AUIPC, want),
                        (family::JUMP_BRANCH_SLT, 0),
                        (family::INIT_TEARDOWN, 0),
                    ]
                },
                "occupancy {occupancy} at height {height}"
            );
        }
    }
}

/// The largest occupancy the 38-bit clock allows, at the smallest height,
/// still fits a `u32` count.
#[test]
fn the_whole_clock_at_the_smallest_height() {
    let plan = plan_shards(&profile(1 << 36), &config(1 << 16));
    assert_eq!(plan.shards[0], (family::ADD_SUB_LUI_AUIPC, 1 << 20));
}

/// A pure function of (profile, config): the same inputs, the same plan;
/// either input changed, a different one.
#[test]
fn the_plan_is_a_pure_function() {
    let (p, c) = (profile(70_000), config(1 << 16));
    assert_eq!(plan_shards(&p, &c), plan_shards(&p, &c));
    assert_ne!(plan_shards(&p, &c), plan_shards(&profile(1), &c));
    assert_ne!(plan_shards(&p, &c), plan_shards(&p, &config(1 << 18)));
}

#[test]
#[should_panic(expected = "not the config's families")]
fn a_profile_of_other_families_is_refused() {
    let mut p = profile(1);
    p.counts.remove(1);
    plan_shards(&p, &config(1 << 16));
}
