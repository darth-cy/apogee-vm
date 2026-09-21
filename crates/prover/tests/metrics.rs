//! The proving metrics harness, `docs/spec/metrics.md`. The whole file is
//! behind the feature, so a default `cargo test --workspace` compiles none of
//! it; CI runs it a second time with `--features metrics`.
//!
//! The cheap tests here drive a [`Recorder`] directly and hold the data model,
//! the aggregation arithmetic and both reports. The one end-to-end test is
//! `#[ignore]`d with the rest of the deferred suites: it proves the S16
//! statement twice and holds the metered block to the plain one **byte for
//! byte**, which is the property that makes the harness safe to leave in.
#![cfg(feature = "metrics")]

use prover::metrics::{
    ByteClass, ProvingMetrics, Recorder, ShardId, ShardShape, Stage, BYTE_CLASSES, STAGES,
};

/// `Stage as usize` indexes [`STAGES`], every parent is a root, and no two
/// stages share a name. The report's tree is built from exactly these three
/// facts, so a stage appended without them would print in the wrong place.
#[test]
fn the_stage_table_is_its_own_index() {
    for (i, stage) in STAGES.iter().enumerate() {
        assert_eq!(*stage as usize, i, "{stage:?} is not at its own index");
    }
    for stage in STAGES {
        if let Some(parent) = stage.parent() {
            assert!(
                parent.parent().is_none(),
                "{stage:?}'s parent {parent:?} is itself a child: the report is one deep"
            );
        }
    }
    let mut names: Vec<&str> = STAGES.iter().map(|s| s.name()).collect();
    names.sort_unstable();
    let n = names.len();
    names.dedup();
    assert_eq!(names.len(), n, "two stages share a name");

    let mut classes: Vec<&str> = BYTE_CLASSES.iter().map(|c| c.name()).collect();
    classes.sort_unstable();
    let n = classes.len();
    classes.dedup();
    assert_eq!(classes.len(), n, "two byte classes share a name");
    for (i, class) in BYTE_CLASSES.iter().enumerate() {
        assert_eq!(*class as usize, i, "{class:?} is not at its own index");
    }
}

/// **Only the base layer and the forward pass are resident at a shard's peak.**
/// The model rests on this and on nothing else, so it is pinned here rather
/// than left to a comment.
#[test]
fn the_peak_model_counts_the_two_classes_that_are_live_together() {
    let resident: Vec<&str> = BYTE_CLASSES
        .iter()
        .filter(|c| c.resident_at_shard_peak())
        .map(|c| c.name())
        .collect();
    assert_eq!(resident, vec!["base_layer", "forward_layers"]);
}

/// A recorder built by hand: spans land where they are opened, `absorb` merges
/// a task's samples into the run's, and every aggregate reads back.
#[test]
fn a_recorder_records_what_it_is_told_and_merges_in_order() {
    let a = ShardId::new(1, 0);
    let b = ShardId::new(1, 1);

    let mut run = Recorder::new();
    let region = run.start(Stage::BlockGkrRegion);

    let mut first = Recorder::for_shard(a);
    let s = first.start(Stage::ShardGkrTotal);
    first.end(s);
    first.bytes(ByteClass::BaseLayer, 100);
    first.bytes(ByteClass::ForwardLayers, 900);
    first.bytes(ByteClass::GkrProof, 7);
    first.note_shard(shape(a));

    let mut second = Recorder::for_shard(b);
    let s = second.start(Stage::ShardGkrTotal);
    second.end(s);
    second.bytes(ByteClass::BaseLayer, 50);
    second.bytes(ByteClass::ForwardLayers, 150);
    second.note_shard(shape(b));

    run.end(region);
    run.absorb(first);
    run.absorb(second);
    let m = run.finish();

    assert_eq!(m.count(Stage::ShardGkrTotal), 2);
    assert_eq!(m.count(Stage::BlockGkrRegion), 1);
    assert_eq!(m.count(Stage::ShardBatchOpen), 0, "a stage never entered");
    assert_eq!(m.class_bytes(ByteClass::BaseLayer), 150);
    assert_eq!(m.class_bytes(ByteClass::ForwardLayers), 1050);

    // A shard's peak is its base layer plus its forward pass, and the proof
    // bytes it also recorded are not part of it.
    assert_eq!(m.shard_peak_bytes(a), 1000);
    assert_eq!(m.shard_peak_bytes(b), 200);
    assert_eq!(m.shard_peaks(), vec![(a, 1000), (b, 200)], "largest first");

    // Shards are put back into statement order however they were absorbed.
    assert_eq!(
        m.shards.iter().map(|s| s.shard).collect::<Vec<_>>(),
        vec![a, b]
    );
}

/// **A structure built twice is not two structures.** `advance` builds each
/// shard's base layer once for the GKR phase and again for the opening phase,
/// so a shard has two `base_layer` samples and one `forward_layers` sample;
/// the peak is the largest of each class, never the sum. Summing would have
/// reported this shard at 1,150 bytes and every real block about a base layer
/// too large.
#[test]
fn a_shard_peak_takes_the_largest_sample_of_each_class_not_their_sum() {
    let id = ShardId::new(2, 0);
    let mut task = Recorder::for_shard(id);
    task.bytes(ByteClass::BaseLayer, 100);
    task.bytes(ByteClass::ForwardLayers, 900);
    task.bytes(ByteClass::BaseLayer, 150); // the opening phase rebuilds it
    task.note_shard(shape(id));
    let mut run = Recorder::new();
    run.absorb(task);
    let m = run.finish();

    assert_eq!(m.shard_peak_bytes(id), 150 + 900);
    // The class total is still the run's cumulative allocation, which is a
    // different question and keeps both samples.
    assert_eq!(m.class_bytes(ByteClass::BaseLayer), 250);
}

/// A shard notes its shape twice — once from `gkr_part`, which has no proof
/// yet, and once from `opening_part`, which has. The report keeps the complete
/// one and shows the shard once.
#[test]
fn a_shard_appears_once_and_with_its_proof_size() {
    let id = ShardId::new(4, 2);
    let mut task = Recorder::for_shard(id);
    let mut early = shape(id);
    early.proof_bytes = 0;
    task.note_shard(early);
    task.note_shard(shape(id));
    let mut run = Recorder::new();
    run.absorb(task);
    let m = run.finish();
    assert_eq!(m.shards.len(), 1, "one row a shard");
    assert_eq!(m.shards[0].proof_bytes, 57_100, "the complete one");
}

/// **The block peak model is the thread count's price**, and that is the whole
/// reason the harness exists: on one thread a block holds one shard, on many
/// it holds one per worker, and the number changes by the largest ones.
#[test]
fn the_modelled_block_peak_follows_the_thread_count() {
    let peaks = [1000u64, 800, 600, 400];
    let mut run = Recorder::new();
    for (i, bytes) in peaks.iter().enumerate() {
        let id = ShardId::new(1, i as u32);
        let mut task = Recorder::for_shard(id);
        task.bytes(ByteClass::ForwardLayers, *bytes);
        task.note_shard(shape(id));
        run.absorb(task);
    }
    let m = run.finish();
    assert_eq!(m.shard_peaks().len(), 4);

    // The model takes the `min(threads, shards)` largest. The recorder read
    // the real thread count, so assert against it rather than a guess.
    let threads = m.environment.rayon_threads;
    let want: u64 = peaks.iter().take(threads.min(4)).sum();
    assert_eq!(m.modelled_block_peak(), want);
    assert!(
        m.modelled_block_peak() >= 1000,
        "even on one thread the largest shard is resident"
    );
}

/// A root stage's unattributed remainder is the gap the report prints, and it
/// is a signed quantity on purpose: a negative one means the children overlap,
/// which for a parallel region is the normal case and not an error.
#[test]
fn the_unattributed_remainder_is_the_gap_between_a_parent_and_its_children() {
    let mut run = Recorder::new();
    let parent = run.start(Stage::GlobalCommitTotal);
    let child = run.start(Stage::GlobalCommitMsm);
    run.end(child);
    run.end(parent);
    let m = run.finish();
    assert!(
        m.unattributed(Stage::GlobalCommitTotal) >= 0,
        "a parent measured around its children cannot be shorter than them"
    );
    assert_eq!(
        m.unattributed(Stage::StatementColumns),
        0,
        "a stage never entered has no remainder"
    );
}

/// Both reports render from an empty recorder and from a full one, and the
/// JSON's braces balance. A report that panicked on a phase nobody ran would
/// be found only in the middle of a long proving run.
#[test]
fn both_reports_render() {
    let empty = Recorder::new().finish();
    let text = format!("{empty}");
    assert!(text.contains("prover metrics"));
    assert!(balanced(&empty.to_json()), "empty JSON balances");

    let mut run = Recorder::new();
    let id = ShardId::new(3, 0);
    let total = run.start(Stage::BlockTotal);
    let mut task = Recorder::for_shard(id);
    let s = task.start(Stage::ShardGkrTotal);
    task.end(s);
    let s = task.start(Stage::ShardForward);
    task.end(s);
    task.bytes(ByteClass::BaseLayer, 1 << 20);
    task.bytes(ByteClass::ForwardLayers, 1 << 24);
    task.note_shard(shape(id));
    run.end(total);
    run.absorb(task);
    run.note_archive_phase(0, 1234);
    let m = run.finish();

    let text = format!("{m}");
    for needle in [
        "prover metrics",
        "block_total",
        "shard_forward",
        "forward_layers",
        "modelled block peak",
        "archive phases",
    ] {
        assert!(
            text.contains(needle),
            "the report does not mention {needle}"
        );
    }
    let json = m.to_json();
    assert!(balanced(&json), "JSON braces balance");
    for needle in [
        "\"environment\"",
        "\"stages\"",
        "\"bytes\"",
        "\"shards\"",
        "\"modelled_block_peak_bytes\"",
    ] {
        assert!(json.contains(needle), "the JSON has no {needle}");
    }
}

/// The report says which build it came from, because a `dev`-profile timing
/// table read as a `release` one is worse than no table.
#[test]
fn the_report_names_its_build() {
    let m = Recorder::new().finish();
    let text = format!("{m}");
    if m.environment.debug_assertions {
        assert!(text.contains("timings are NOT release timings"));
    } else {
        assert!(text.contains("release"));
    }
}

fn shape(shard: ShardId) -> ShardShape {
    ShardShape {
        shard,
        height: 1 << 20,
        ts_window: [0, 4],
        gkr_layers: 3,
        sumcheck_rounds: 60,
        final_evals: 9,
        witness_commitments: 31,
        proof_bytes: 57_100,
    }
}

fn balanced(json: &str) -> bool {
    let mut depth = 0i32;
    for c in json.chars() {
        match c {
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            _ => {}
        }
        if depth < 0 {
            return false;
        }
    }
    depth == 0
}

// ---------------------------------------------------------------------------
// The end-to-end property, deferred with the other real-proof suites
// ---------------------------------------------------------------------------

mod common;

/// **The harness changes no proof byte.** S16's statement proved twice, once
/// through `prove_block` and once through `prove_block_metered`, and the two
/// blocks compared on the wire. This is the property that makes it safe to
/// build the prover with the feature on and believe the result.
///
/// Deferred: it proves the S16 statement twice, about 8.6 GB a time.
#[test]
#[ignore]
fn a_metered_block_is_the_block_prove_block_makes() {
    use trace::plan_shards;

    let setup = common::setup();
    let plan = plan_shards(
        common::archive(&setup.program).cycle_profile(),
        &setup.vk.config,
    );

    let mut plain_archive = common::archive(&setup.program);
    let plain = prover::prove_block(&setup, &mut plain_archive, &plan).expect("the block");

    let mut metered_archive = common::archive(&setup.program);
    let (metered, metrics) =
        prover::prove_block_metered(&setup, &mut metered_archive, &plan).expect("the block");

    assert_eq!(
        plain.to_bytes(),
        metered.to_bytes(),
        "the metered block is the plain one, byte for byte"
    );

    // And the metrics describe that run rather than an empty one.
    assert!(metrics.total(Stage::BlockTotal) > 0);
    assert!(metrics.total(Stage::ShardForward) > 0);
    assert_eq!(metrics.count(Stage::ShardGkrTotal), metrics.shards.len());
    assert_eq!(
        metrics.count(Stage::ShardColumnsTotal),
        2 * metrics.shards.len(),
        "a full block builds every shard's committed columns twice, once in \
         each of `advance`'s two parallel regions, which drop them in between \
         so a killed run can resume from the archive. It is not three: \
         `statement_inputs` takes the `M`-only path"
    );
    assert_eq!(
        metrics.count(Stage::StatementShardFill),
        metrics.shards.len(),
        "the statement builds each shard's `M` columns once, and counts no \
         multiplicities to do it"
    );
    assert!(
        metrics.total(Stage::StatementColumns) < metrics.total(Stage::ShardColumnsTotal),
        "the `M`-only path is the cheap one: it runs the fill and stops, where \
         `shard_columns` goes on to count every channel's multiplicities"
    );
    assert_eq!(metrics.count(Stage::ShardGkrTask), metrics.shards.len());
    assert!(
        metrics.total(Stage::ShardGkrTask) >= metrics.total(Stage::ShardGkrTotal),
        "a task's body contains its `gkr_part`"
    );
    assert!(metrics.modelled_block_peak() > 0);
    assert_eq!(metrics.proof.block_bytes, plain.to_bytes().len());
    println!("{metrics}");
}

/// A convenience the report is for: the numbers a handoff note quotes, printed
/// in one place for one statement. Deferred with the suite above.
#[test]
#[ignore]
fn the_report_of_the_s16_statement() {
    let setup = common::setup();
    let mut archive = common::archive(&setup.program);
    let plan = trace::plan_shards(archive.cycle_profile(), &setup.vk.config);
    let (_, metrics) = prover::prove_block_metered(&setup, &mut archive, &plan).expect("the block");
    println!("{metrics}");
    println!("{}", metrics.to_json());
}

/// Two aggregates the deferred runs above are read through, held to their
/// definitions on data the cheap tests can build.
/// The speedup is **one task's whole body** over the region's wall, not
/// `gkr_part` over it. The region waits for each task to build its shard's
/// columns too, and measuring only `gkr_part` against the wall read 0.84× on
/// the S16 statement — not a speedup at all, and not what the region did.
#[test]
fn the_speedup_is_a_task_body_over_the_region_wall() {
    assert_eq!(
        ProvingMetrics::gkr_speedup(&Recorder::new().finish()),
        None,
        "no region, no speedup"
    );

    let mut run = Recorder::new();
    let region = run.start(Stage::BlockGkrRegion);
    // Enough work that the span is measurably above zero on any clock.
    let mut x = 0u64;
    for i in 0..500_000u64 {
        x = x.wrapping_add(i).rotate_left(3);
    }
    std::hint::black_box(x);
    run.end(region);

    let mut task = Recorder::for_shard(ShardId::new(1, 0));
    let s = task.start(Stage::ShardGkrTask);
    task.end(s);
    let s = task.start(Stage::ShardGkrTotal);
    task.end(s);
    run.absorb(task);
    let m = run.finish();

    assert!(
        m.total(Stage::BlockGkrRegion) > 0,
        "the region was measurable"
    );
    assert!(m.gkr_speedup().is_some(), "a region that ran has a speedup");
    assert!(m.opening_speedup().is_none(), "a region that did not, none");

    // And it reads the task stage: a run with `gkr_part` timed but no task
    // span has no speedup to report.
    let mut bare = Recorder::new();
    let region = bare.start(Stage::BlockGkrRegion);
    let mut x = 0u64;
    for i in 0..500_000u64 {
        x = x.wrapping_add(i).rotate_left(3);
    }
    std::hint::black_box(x);
    bare.end(region);
    let mut task = Recorder::for_shard(ShardId::new(1, 0));
    let s = task.start(Stage::ShardGkrTotal);
    task.end(s);
    bare.absorb(task);
    assert_eq!(bare.finish().gkr_speedup(), Some(0.0));
}
