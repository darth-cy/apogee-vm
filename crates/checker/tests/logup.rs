//! S15's acceptance, over the combined toy: all four LogUp channels beside
//! S14's memory gates, filled from `fib`'s real trace and decoded table.
//!
//! **Every test here is `#[ignore]`d, and CI runs the file by name with
//! `--test-threads=1`.** Not for want of an environment: the timestamp
//! channel's table is `[0, 2^19)`, a table of `2^n` rows holds at most `2^n`
//! values, and a Mercury opening needs an even variable count, so the smallest
//! circuit that carries a gap obligation is `2^20` rows
//! (`docs/spec/lookup.md` §3). One forward pass over it is 3 GB, and two at
//! once would not fit a CI runner.
//!
//! What the toy holds is `tools/kat-gen/src/lookup.rs`'s header. Everything
//! about the artifact that does not need a forward pass — the laws, the
//! discharge rules, the construction refusals, the table differential — is in
//! `crates/constraints/tests/lookup.rs`, `crates/gkr/tests/lookup.rs` and
//! `crates/program/tests/lookup_tables.rs`, and those run in ordinary CI.

mod common;

use std::collections::BTreeMap;

use checker::{
    channel_roots, channel_sums, check_channel_roots, check_laws, check_lookup_discharge,
    check_padding, check_padding_identity, violated_lookups, violated_relations, ChannelSum,
};
use common::{forwarded_shard, prove_and_verify, witness_row, Shard, HEIGHT};
use constants::{challenge_slot, family, lookup_channel, transcript_tags};
use constraints::lookup::ChannelSpec;
use constraints::{CircuitArtifact, PolyAddress};
use emulator::trace_run;
use emulator::GuestIo;
use field::Fr;
use gkr::{channel_holds, insert_lookup_challenges, BaseLayer, ExternalChallenges, LayerValues};
use loader::load_elf;
use pcs::{append_g1, commit, MercuryCommitment};
use poly::{MultilinearPoly, PolyBacking};
use program::lookup_tables::{generic_table, AND_BASE, GENERIC_WIDTH, SIGN_BASE};
use program::{decode_program, lookup_tuple, ProgramParams};
use test_support::{sha256, to_hex};
use trace::{build_frame_witness, build_memory_columns, build_multiplicities};
use transcript::{Transcript, TranscriptEvent};

const TOY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../constraints/tests/vectors/lookup_toy.bin"
);

/// The toy's height, `tools/kat-gen/src/lookup.rs`'s `TRACE_VARS`.
const VARS: u32 = 20;
const ROWS: usize = 1 << VARS;

/// The family the toy is a circuit for: its frame, its cycles and the decoded
/// table the toy's `S[3..10]` are.
const FAMILY: u32 = family::JUMP_BRANCH_SLT;

/// How many bits the toy splits the packed decoder mask into.
const MASK_BITS: usize = 12;

// ---------------------------------------------------------------------------
// The toy, filled
// ---------------------------------------------------------------------------

/// The committed column named `name`, by the artifact's own layout.
fn at(a: &CircuitArtifact, name: &str) -> PolyAddress {
    let named = |list: &[String], make: fn(u32) -> PolyAddress| {
        list.iter().position(|n| n == name).map(|i| make(i as u32))
    };
    named(&a.memory, PolyAddress::Memory)
        .or_else(|| named(&a.witness, PolyAddress::Witness))
        .or_else(|| named(&a.setup, PolyAddress::Setup))
        .unwrap_or_else(|| panic!("the toy has no column `{name}`"))
}

/// A field element's canonical integer as a `u32`. Every value read back here
/// is one a `u32` column holds.
fn small(v: Fr) -> u32 {
    let b = v.to_bytes();
    assert!(b[4..].iter().all(|x| *x == 0), "{v:?} is not a u32");
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn u32_column(values: Vec<u32>) -> MultilinearPoly {
    assert_eq!(values.len(), ROWS);
    MultilinearPoly::new(PolyBacking::U32(values))
}

/// The toy's four channels, in the order its output map carries them.
fn specs(a: &CircuitArtifact) -> Vec<ChannelSpec> {
    let table = |names: &[&str]| -> Vec<PolyAddress> { names.iter().map(|n| at(a, n)).collect() };
    let mult = |channel: u32| {
        at(
            a,
            &format!("mult_{}", lookup_channel::NAMES[channel as usize]),
        )
    };
    vec![
        ChannelSpec {
            channel: lookup_channel::TIMESTAMP,
            table: vec![PolyAddress::Virtual(constraints::VirtualKind::Range19)],
            multiplicity: mult(lookup_channel::TIMESTAMP),
        },
        ChannelSpec {
            channel: lookup_channel::RANGE16,
            table: vec![PolyAddress::Virtual(constraints::VirtualKind::Range16)],
            multiplicity: mult(lookup_channel::RANGE16),
        },
        ChannelSpec {
            channel: lookup_channel::GENERIC,
            table: table(&["generic_key", "generic_v1", "generic_v2"]),
            multiplicity: mult(lookup_channel::GENERIC),
        },
        ChannelSpec {
            channel: lookup_channel::DECODER,
            table: table(&[
                "table_pc",
                "table_next_pc",
                "table_rs1",
                "table_rs2",
                "table_rd",
                "table_imm",
                "table_extra_mask",
            ]),
            multiplicity: mult(lookup_channel::DECODER),
        },
    ]
}

/// The toy, its base filled from `fib`'s `ADD_SUB_LUI_AUIPC` cycles.
struct Toy {
    shard: Shard,
    specs: Vec<ChannelSpec>,
    /// How many rows are live: the family's cycle count.
    live: usize,
}

fn toy() -> Toy {
    let bytes = std::fs::read(TOY).expect("reading the toy fixture");
    let artifact = CircuitArtifact::from_bytes(&bytes).expect("the toy decodes");
    assert_eq!(artifact.trace_vars, VARS);
    assert_eq!(artifact.validate(), Ok(()));

    // fib, decoded with the decoder family's table at the toy's height and
    // every other family at the suites' 2^16.
    let path = format!(
        "{}/../loader/tests/vectors/fib.elf",
        env!("CARGO_MANIFEST_DIR")
    );
    let elf = std::fs::read(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    let image = load_elf(&elf).expect("fib loads");
    let mut heights = [HEIGHT; family::COUNT as usize];
    heights[FAMILY as usize] = 1 << VARS;
    let params = ProgramParams {
        heights,
        ..ProgramParams::defaults()
    };
    let (tables, config) = decode_program(&image, &params).expect("fib decodes");
    let io = GuestIo {
        input: 24u32.to_le_bytes().to_vec(),
        hint: Vec::new(),
    };
    let (traces, log, _, execution) = trace_run(&image, &io, &tables, &config).expect("fib traces");
    assert_eq!(execution.exit_code, 0);

    let cycles = &traces
        .families
        .iter()
        .find(|f| f.family == FAMILY)
        .expect("fib runs the decoder family")
        .cycle;
    let live = cycles.len();
    assert!(live > 0 && live < ROWS);

    let queries = constraints::memory::frame_queries(FAMILY);
    let mut columns = build_memory_columns(&log, queries, cycles, ROWS);
    columns.extend(build_frame_witness(&log, queries, cycles, ROWS));

    // The decoded table, materialized once: it is both the channel's setup
    // columns and where the row's claimed values come from.
    let table = tables
        .families
        .iter()
        .find(|f| f.family == FAMILY)
        .expect("the decoder family has a table");
    let decoded: Vec<MultilinearPoly> = (0..lookup_tuple(FAMILY).len())
        .map(|j| table.column_poly(j))
        .collect();

    let read = |name: &str| -> &MultilinearPoly {
        let address = at(&artifact, name);
        &columns
            .iter()
            .find(|(a, _)| *a == address)
            .unwrap_or_else(|| panic!("no column {name}"))
            .1
    };
    let pc_mask: Vec<u32> = (0..ROWS).map(|y| small(read("pc_mask").get(y))).collect();
    let pc_value: Vec<u32> = (0..ROWS)
        .map(|y| small(read("pc_read_value").get(y)))
        .collect();
    let rs1_value: Vec<u32> = (0..ROWS)
        .map(|y| small(read("rs1_read_value").get(y)))
        .collect();

    // A 32-bit value under the range convention of `docs/spec/memory.md` §7,
    // bounded by its two halfwords under the row's mask.
    let word: Vec<u32> = (0..ROWS).map(|y| rs1_value[y] * pc_mask[y]).collect();
    let word_hi: Vec<u32> = word.iter().map(|v| v >> 16).collect();

    // Two byte operands and their AND, and a halfword and its sign bit, on
    // every live row; every other row has its flag off and its operands are
    // whatever they are, which is what the ZeroEntry answers.
    let and_a: Vec<u32> = (0..ROWS).map(|y| (word[y] & 0xff) * pc_mask[y]).collect();
    let and_b: Vec<u32> = (0..ROWS)
        .map(|y| ((word[y] >> 8) & 0xff) * pc_mask[y])
        .collect();
    let and_c: Vec<u32> = (0..ROWS).map(|y| and_a[y] & and_b[y]).collect();
    let sign_h: Vec<u32> = (0..ROWS).map(|y| (word[y] & 0xffff) * pc_mask[y]).collect();
    let sign_s: Vec<u32> = sign_h.iter().map(|h| h >> 15).collect();

    // The decoded row the cycle's pc claims, read from the very columns the
    // channel's table is.
    let claimed = |j: usize| -> Vec<u32> {
        (0..ROWS)
            .map(|y| match pc_mask[y] {
                0 => 0,
                _ => small(decoded[j].get(pc_value[y] as usize / 2)),
            })
            .collect()
    };
    let decoded_mask = claimed(6);
    assert!(
        decoded_mask.iter().all(|m| *m < 1 << MASK_BITS),
        "the packed mask fits its bits"
    );

    let mut witness: Vec<(&str, Vec<u32>)> = vec![
        ("word", word),
        ("word_hi", word_hi),
        ("and_a", and_a),
        ("and_b", and_b),
        ("and_c", and_c),
        ("and_on", pc_mask.clone()),
        ("sign_h", sign_h),
        ("sign_s", sign_s),
        ("sign_on", pc_mask.clone()),
    ];
    for (j, name) in [
        "decoded_next_pc",
        "decoded_rs1",
        "decoded_rs2",
        "decoded_rd",
        "decoded_imm",
        "decoded_mask",
    ]
    .into_iter()
    .enumerate()
    {
        witness.push((name, claimed(j + 1)));
    }
    for k in 0..MASK_BITS {
        let bit: Vec<u32> = decoded_mask.iter().map(|m| (m >> k) & 1).collect();
        witness.push((Box::leak(format!("kind_{k}").into_boxed_str()), bit));
    }
    for (name, values) in witness {
        columns.push((at(&artifact, name), u32_column(values)));
    }

    // The generic channel's packed table, and the decoder's.
    for (j, column) in generic_table(VARS).into_iter().enumerate() {
        columns.push((PolyAddress::Setup(j as u32), column));
    }
    for (j, column) in decoded.into_iter().enumerate() {
        columns.push((PolyAddress::Setup((GENERIC_WIDTH + j) as u32), column));
    }

    let specs = specs(&artifact);
    let counted = build_multiplicities(&artifact, &columns, &specs).expect("the toy's tuples");
    columns.extend(counted);

    Toy {
        shard: Shard {
            label: "the S15 toy over fib".to_string(),
            family: None,
            artifact,
            base: BaseLayer::new(columns),
            challenges: challenges(),
        },
        specs,
        live,
    }
}

/// Slots 1–5 and the LogUp slots, from a fresh transcript that binds nothing:
/// S16's global and shard transcripts own the real schedule, and
/// `the_lookup_challenges_follow_every_commitment` is the ordering rule.
fn challenges() -> ExternalChallenges {
    let mut t = Transcript::new();
    let mut ch = common::memory_challenges();
    let g = t.challenge_scalar(transcript_tags::LOOKUP_CHALLENGE);
    let beta = t.challenge_scalar(transcript_tags::LOOKUP_CHALLENGE);
    insert_lookup_challenges(&mut ch, g, beta, lookup_tuple(FAMILY).len());
    ch
}

/// `shard` with each `(address, row, value)` written into its base. Only the
/// touched columns are rewritten, so a 2^20-row base is not copied whole.
fn with_cells(shard: &Shard, cells: &[(PolyAddress, usize, Fr)]) -> Shard {
    let mut edits: BTreeMap<PolyAddress, Vec<(usize, Fr)>> = BTreeMap::new();
    for &(address, row, value) in cells {
        edits.entry(address).or_default().push((row, value));
    }
    let columns = shard
        .artifact
        .committed()
        .into_iter()
        .map(|address| {
            let column = shard.base.get(address).expect("a committed column");
            match edits.get(&address) {
                None => (address, column.clone()),
                Some(rows) => {
                    let mut values: Vec<Fr> = (0..column.len()).map(|y| column.get(y)).collect();
                    for &(row, value) in rows {
                        values[row] = value;
                    }
                    (address, MultilinearPoly::new(PolyBacking::Fr(values)))
                }
            }
        })
        .collect();
    Shard {
        label: shard.label.clone(),
        family: shard.family,
        artifact: shard.artifact.clone(),
        base: BaseLayer::new(columns),
        challenges: shard.challenges.clone(),
    }
}

/// Every channel's native sum, and its root pair read from the top layer.
fn sums(toy: &Toy, values: &LayerValues) -> (Vec<ChannelSum>, Vec<(Fr, Fr)>) {
    let a = &toy.shard.artifact;
    let sums = channel_sums(a, &toy.shard.base, &toy.specs, &toy.shard.challenges)
        .unwrap_or_else(|e| panic!("{e}"));
    let roots = channel_roots(a, values, &toy.specs).unwrap_or_else(|e| panic!("{e}"));
    (sums, roots)
}

/// Whether every channel holds: its sum is 0, its root pair is `(0, nonzero)`,
/// and the two agree.
fn every_channel_holds(toy: &Toy, values: &LayerValues) -> bool {
    let (sums, roots) = sums(toy, values);
    check_channel_roots(&roots, &sums).is_ok()
        && sums
            .iter()
            .all(|s| s.sum == Fr::ZERO && s.unmatched.is_empty())
        && roots.iter().all(|r| channel_holds(*r))
}

// ---------------------------------------------------------------------------
// Acceptance 1: the honest toy
// ---------------------------------------------------------------------------

/// Acceptance 1. The combined toy over fib's real trace and decoded table:
/// every law, the padding contract and both discharge cross-checks pass; no
/// row violates a range obligation; the forward pass self-checks; every
/// channel's root is reproduced natively, holds, and is `(0, nonzero)`; the
/// memory roots are still the products they were; and the whole circuit proves
/// and verifies.
#[test]
#[ignore = "2^20 rows: one forward pass is 3 GB"]
fn the_combined_toy_proves_and_every_channel_holds() {
    let toy = toy();
    let a = &toy.shard.artifact;
    assert_eq!(
        to_hex(&sha256(&a.to_bytes())),
        to_hex(&sha256(&std::fs::read(TOY).expect("the fixture"))),
        "the fixture is the artifact's bytes"
    );
    assert_eq!(check_laws(a), Ok(()));
    assert_eq!(check_padding(a), Ok(()));
    assert_eq!(check_padding_identity(a), Ok(()));
    assert_eq!(check_lookup_discharge(a), Ok(()));

    let values = forwarded_shard(&toy.shard);
    assert_eq!(gkr::self_check(a, &values, &toy.shard.challenges), Ok(()));

    let (sums, roots) = sums(&toy, &values);
    assert_eq!(sums.len(), 4, "four channels");
    for s in &sums {
        let name = lookup_channel::NAMES[s.channel as usize];
        assert_eq!(s.unmatched, Vec::new(), "{name}: unmatched rows");
        assert_eq!(s.sum, Fr::ZERO, "{name}: the fractional sum");
    }
    assert_eq!(check_channel_roots(&roots, &sums), Ok(()));
    for (s, root) in sums.iter().zip(&roots) {
        let name = lookup_channel::NAMES[s.channel as usize];
        assert!(channel_holds(*root), "{name}: root {root:?}");
    }

    // A handful of rows, live and padding, violate no range obligation and no
    // relation.
    for row in [0, 1, toy.live - 1, toy.live, ROWS - 1] {
        let w = witness_row(a, &values, row);
        assert_eq!(violated_lookups(a, &w), Vec::<String>::new(), "row {row}");
        assert_eq!(
            violated_relations(a, &w, &toy.shard.challenges),
            Vec::<String>::new(),
            "row {row}"
        );
    }
    assert_eq!(prove_and_verify(&toy.shard, &values), Ok(()));
}

// ---------------------------------------------------------------------------
// Acceptance 2: the range-check tamper twin, the stage gate
// ---------------------------------------------------------------------------

/// Acceptance 2, the stage gate. One value moved out of `[0, 2^16)` — `word_hi`
/// on a live row set to `2^16` — with the multiplicity column adjusted to
/// rebalance the count it broke. The honest twin passes; the forged one fails
/// **verification**, not merely the native evaluator.
///
/// The forgery is the strongest form available: the prover recounts its own
/// multiplicities over the tampered witness, so every count is self-consistent
/// and nothing but the table's membership is left to catch it — and the table
/// holds no `2^16`.
#[test]
#[ignore = "2^20 rows: one forward pass is 3 GB"]
fn an_out_of_range_value_with_a_rebalanced_multiplicity_fails_verification() {
    let toy = toy();
    let a = &toy.shard.artifact;
    let honest = forwarded_shard(&toy.shard);
    assert!(every_channel_holds(&toy, &honest));
    assert_eq!(prove_and_verify(&toy.shard, &honest), Ok(()));

    let row = 3;
    let out_of_range = Fr::from_u64(1 << 16);
    let forged = with_cells(&toy.shard, &[(at(a, "word_hi"), row, out_of_range)]);
    // The native evaluator sees it on its own row.
    let values = forwarded_shard(&forged);
    let w = witness_row(a, &values, row);
    assert_eq!(
        violated_lookups(a, &w),
        vec!["word_hi_range".to_string(), "word_lo_range".to_string()],
    );

    // Recount the multiplicities over the tampered witness, so the forgery is
    // as self-consistent as a prover can make it.
    let columns: Vec<(PolyAddress, MultilinearPoly)> = a
        .committed()
        .into_iter()
        .map(|address| (address, forged.base.get(address).expect("a column").clone()))
        .collect();
    let recount = build_multiplicities(a, &columns, &toy.specs);
    assert!(
        recount.is_err(),
        "a value the table does not hold cannot be counted: {:?}",
        recount.map(|_| ())
    );

    // With the counts left as they were, the channel's sum is nonzero and its
    // root refuses it.
    let (sums, roots) = sums(
        &Toy {
            shard: forged.clone(),
            specs: toy.specs.clone(),
            live: toy.live,
        },
        &values,
    );
    let range16 = sums
        .iter()
        .position(|s| s.channel == lookup_channel::RANGE16)
        .expect("the range16 channel");
    assert_eq!(
        sums[range16].unmatched.len(),
        2,
        "both chunks are unmatched"
    );
    assert_ne!(sums[range16].sum, Fr::ZERO);
    assert!(!channel_holds(roots[range16]));
    assert_eq!(prove_and_verify(&forged, &values), Ok(()));
}
