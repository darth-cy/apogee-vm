//! S15's acceptance, over the combined toy: all four LogUp channels beside
//! S14's memory gates, filled from `fib`'s real trace and decoded table.
//!
//! **Every test here is `#[ignore]`d, and CI runs the file by name with
//! `--include-ignored --test-threads=1`.** `--include-ignored`, not
//! `--ignored`, for the reason `.github/workflows/ci.yml` gives of the qemu
//! step: the latter runs *only* ignored tests, so a case added here without the
//! attribute would be filtered out of the one step meant to run it. Not for
//! want of an environment: the timestamp
//! channel's table is `[0, 2^19)`, a table of `2^n` rows holds at most `2^n`
//! values, and a Mercury opening needs an even variable count, so the smallest
//! circuit that carries a gap obligation is `2^20` rows
//! (`docs/spec/lookup.md` §3). One forward pass over it holds 144,703,478
//! inner cells — 4.63 GB as `Fr` — and two at once would not fit a CI runner.
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
use common::{forwarded_shard, witness_row, Shard, HEIGHT};
use constants::{challenge_slot, family, lookup_channel, transcript_tags};
use constraints::lookup::ChannelSpec;
use constraints::{CircuitArtifact, PolyAddress};
use emulator::trace_run;
use emulator::GuestIo;
use field::Fr;
use gkr::{channel_holds, insert_lookup_challenges, BaseLayer, LayerValues};
use loader::load_elf;
use pcs::{append_g1, commit, MercuryCommitment};
use poly::{MultilinearPoly, PolyBacking};
use program::lookup_tables::{generic_table, GENERIC_WIDTH, SIGN_BASE};
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

/// The toy, its base filled from `fib`'s own cycles and decoded table.
struct Toy {
    shard: Shard,
    specs: Vec<ChannelSpec>,
    /// How many rows are live: the family's cycle count.
    live: usize,
    /// The shard transcript after every committed column is absorbed and `g`
    /// and `β` are drawn: what a proof of this shard starts from.
    seeded: transcript::TranscriptSnapshot,
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
        stdin: Vec::new(),
        advice: Vec::new(),
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

    // The shard's own transcript, in S16's order: every committed column's
    // commitment absorbed, then `g` and `β` drawn under one challenge tag. The
    // memory slots are the global argument's and come from a sponge of their
    // own, as S14's harness draws them.
    let base = BaseLayer::new(columns);
    let mut t = Transcript::new();
    absorb_commitments(&mut t, &artifact, &base);
    let mut challenges = common::memory_challenges();
    let g = t.challenge_scalar(transcript_tags::LOOKUP_CHALLENGE);
    let beta = t.challenge_scalar(transcript_tags::LOOKUP_CHALLENGE);
    insert_lookup_challenges(&mut challenges, g, beta, &artifact);

    Toy {
        shard: Shard {
            label: "the S15 toy over fib".to_string(),
            family: None,
            artifact,
            base,
            challenges,
        },
        specs,
        live,
        seeded: t.snapshot(),
    }
}

/// Every committed column's Mercury commitment, absorbed as a `COMMITMENT`
/// message of four `Fr` limbs — the base binding S16 uses, and the one a shard's
/// local challenges must follow (`docs/spec/lookup.md` §2).
fn absorb_commitments(t: &mut Transcript, a: &CircuitArtifact, base: &BaseLayer) {
    let srs = toy_srs(a.trace_vars);
    for address in a.committed() {
        let column = base.get(address).expect("a committed column");
        let MercuryCommitment(point) = commit(&srs, column).expect("the column commits");
        append_g1(t, transcript_tags::COMMITMENT, &point);
    }
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
            .all(|s| s.num == Fr::ZERO && s.unmatched.is_empty())
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
#[ignore = "2^20 rows: one forward pass holds 4.63 GB of inner cells"]
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
    assert_eq!(check_lookup_discharge(a, &toy.specs), Ok(()));

    let values = forwarded_shard(&toy.shard);
    assert_eq!(gkr::self_check(a, &values, &toy.shard.challenges), Ok(()));

    let (sums, roots) = sums(&toy, &values);
    assert_eq!(sums.len(), 4, "four channels");
    for s in &sums {
        let name = lookup_channel::NAMES[s.channel as usize];
        assert_eq!(s.unmatched, Vec::new(), "{name}: unmatched rows");
        assert_eq!(s.num, Fr::ZERO, "{name}: the fractional sum's numerator");
        assert_ne!(s.den, Fr::ZERO, "{name}: its denominator");
        assert_eq!(s.sum(), Some(Fr::ZERO), "{name}: the sum");
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
    assert_eq!(prove_and_verify(&toy, &values), Ok(()));
}

// ---------------------------------------------------------------------------
// Acceptance 2: the range-check tamper twin, the stage gate
// ---------------------------------------------------------------------------

/// Acceptance 2, the stage gate. One value moved out of `[0, 2^16)` — `word_hi`
/// on a live row set to `2^16` — with the multiplicity column adjusted to
/// rebalance the count it broke. The honest twin passes; the forged one fails
/// **verification**, not merely the native evaluator.
///
/// Two forgeries, and the second is the interesting one. The prover first
/// recounts its own multiplicities over the tampered witness, which cannot even
/// be done: the table holds no `2^16`. Then it does what an unconstrained prover
/// would — choose a multiplicity cell **after** `g`, solving
/// `δ = (num/den)·(T_0 + g)` — and the channel balances, every check accepts it,
/// and the proof verifies. What forbids that is the order of
/// `docs/spec/lookup.md` §2 and nothing in the circuit, which is why acceptance
/// 3 is a test and not a remark.
#[test]
#[ignore = "2^20 rows: one forward pass holds 4.63 GB of inner cells"]
fn an_out_of_range_value_with_a_rebalanced_multiplicity_fails_verification() {
    let toy = toy();
    let a = &toy.shard.artifact;
    let honest = forwarded_shard(&toy.shard);
    assert!(every_channel_holds(&toy, &honest));
    assert_eq!(prove_and_verify(&toy, &honest), Ok(()));

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
    let forged_toy = reshard(&toy, forged);
    let (broken, roots) = sums(&forged_toy, &values);
    let range16 = broken
        .iter()
        .position(|s| s.channel == lookup_channel::RANGE16)
        .expect("the range16 channel");
    assert_eq!(
        broken[range16].unmatched.len(),
        2,
        "both chunks are unmatched"
    );
    assert_ne!(broken[range16].num, Fr::ZERO);
    assert!(!channel_holds(roots[range16]));
    // The GKR proof of the forged witness is honest — nothing below the root
    // notices — and the root check is what refuses it. A prover claiming the
    // honest root instead is refused by the engine.
    assert_eq!(prove_and_verify(&forged_toy, &values), Ok(()));
    assert_eq!(
        verify_claiming(
            &forged_toy,
            &values,
            &[(range16, Fr::ZERO, roots[range16].1)]
        ),
        Err(gkr::GkrError::LayerInconsistency {
            layer: a.depth() - 1
        }),
        "a forged output claim, refused at the top transition"
    );

    // The other half of the item: a multiplicity chosen **after** `g`
    // rebalances the channel outright. A multiplicity is a field vector, so a
    // prover who knew `g` could add `δ = (num/den)·(T_0 + g)` at table row 0 and
    // drive the channel's numerator to 0. What forbids it is the order of
    // `docs/spec/lookup.md` §2 — every multiplicity commitment absorbed before
    // `g` is drawn — and nothing in the circuit;
    // `the_lookup_challenges_follow_every_commitment` is that order.
    let g = toy
        .shard
        .challenges
        .get(challenge_slot::LOOKUP_G)
        .expect("g was supplied");
    let table_0 = gkr::virtual_at_row(constraints::VirtualKind::Range16, 0) + g;
    let delta = broken[range16].num
        * broken[range16]
            .den
            .inverse()
            .expect("a nonzero denominator")
        * table_0;
    let mult = toy.specs[range16].multiplicity;
    let was = forged_toy.shard.base.get(mult).expect("a column").get(0);
    let rebalanced = with_cells(&forged_toy.shard, &[(mult, 0, was + delta)]);
    let values = forwarded_shard(&rebalanced);
    let rebalanced_toy = reshard(&toy, rebalanced);
    let (after, roots) = sums(&rebalanced_toy, &values);
    assert_eq!(
        after[range16].num,
        Fr::ZERO,
        "a multiplicity chosen after g rebalances the channel"
    );
    assert!(channel_holds(roots[range16]), "and its root accepts it");
    assert_eq!(check_channel_roots(&roots, &after), Ok(()));
    assert_eq!(prove_and_verify(&rebalanced_toy, &values), Ok(()));
    // It is still not a count: no multiset of lookups produces it.
    let recount = build_multiplicities(a, &columns_of(&rebalanced_toy.shard), &toy.specs);
    assert!(recount.is_err(), "and it is still not a recount");
}

// ---------------------------------------------------------------------------
// Acceptance 3: the shard-local challenges follow every commitment
// ---------------------------------------------------------------------------

/// Acceptance 3, structurally, from the recorded transcript event log: every
/// `g`/`β` sample strictly follows the absorb of every witness and multiplicity
/// commitment of the shard.
///
/// The script is the one S16 wires into a shard: commit each column, absorb it
/// as a `COMMITMENT` message of four `Fr` limbs, and only then draw the two
/// challenges under `LOOKUP_CHALLENGE`. The log is metadata — it never feeds
/// the sponge — so reading it changes nothing.
#[test]
#[ignore = "2^20 rows: a toy SRS of 2^20 points and one commitment per column"]
fn the_lookup_challenges_follow_every_commitment() {
    let toy = toy();
    let a = &toy.shard.artifact;
    let srs = toy_srs(a.trace_vars);

    // The witness subtree, the multiplicity columns last in it.
    let witness: Vec<PolyAddress> = (0..a.witness.len() as u32)
        .map(PolyAddress::Witness)
        .collect();
    let multiplicities: Vec<&String> = a.witness.iter().rev().take(4).collect();
    assert!(
        multiplicities.iter().all(|n| n.starts_with("mult_")),
        "the multiplicity columns are last in the witness subtree: {multiplicities:?}"
    );

    let mut t = Transcript::new();
    for address in &witness {
        let column = toy.shard.base.get(*address).expect("a committed column");
        let MercuryCommitment(point) = commit(&srs, column).expect("the column commits");
        append_g1(&mut t, transcript_tags::COMMITMENT, &point);
    }
    let absorbs = t.event_log().len();
    let g = t.challenge_scalar(transcript_tags::LOOKUP_CHALLENGE);
    let beta = t.challenge_scalar(transcript_tags::LOOKUP_CHALLENGE);
    assert_ne!(g, beta, "two draws, two values");

    // The log, event for event: one absorb per column, then the two challenges.
    let log = t.event_log();
    let expected: Vec<TranscriptEvent> = witness
        .iter()
        .map(|_| TranscriptEvent::Absorb {
            tag: transcript_tags::COMMITMENT,
            n_scalars: 4,
        })
        .chain(
            [TranscriptEvent::Challenge {
                tag: transcript_tags::LOOKUP_CHALLENGE,
            }; 2],
        )
        .collect();
    assert_eq!(log, expected.as_slice());

    // And the ordering invariant, over whatever log it is handed: no sample
    // under the lookup tag precedes an absorb of a commitment.
    let last_absorb = log
        .iter()
        .rposition(|e| matches!(e, TranscriptEvent::Absorb { tag, .. } if *tag == transcript_tags::COMMITMENT))
        .expect("a commitment was absorbed");
    let first_sample = log
        .iter()
        .position(|e| matches!(e, TranscriptEvent::Challenge { tag } if *tag == transcript_tags::LOOKUP_CHALLENGE))
        .expect("a challenge was drawn");
    assert!(
        last_absorb < first_sample,
        "every g/beta sample follows every commitment absorb"
    );
    assert_eq!(absorbs, last_absorb + 1);
}

/// An SRS of `2^power` powers of a `tau` written down here, built the way
/// `crates/pcs`' suite builds one: real, structurally valid and completely
/// insecure. Only `commit` is used — an opening is S16's.
fn toy_srs(power: u32) -> srs::Srs {
    use curve::{G1Projective, G2Affine};
    use rayon::prelude::*;

    let tau = Fr::from_hex("0x0000000000000000000000000000000000000000000000000000000000abcdef")
        .expect("a canonical literal");
    let count = 1usize << power;
    let mut scalars = Vec::with_capacity(count);
    let mut acc = Fr::ONE;
    for _ in 0..count {
        scalars.push(acc);
        acc *= tau;
    }
    let projective: Vec<G1Projective> = scalars
        .par_iter()
        .map(|s| G1Projective::GENERATOR.mul(s))
        .collect();
    let g1 = G1Projective::batch_to_affine(&projective);
    let g2_tau = G2Affine::GENERATOR.mul(&tau);

    let mut bytes = Vec::with_capacity(280 + count * 64);
    bytes.extend_from_slice(b"APOGESRS");
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&power.to_le_bytes());
    bytes.extend_from_slice(&(count as u64).to_le_bytes());
    bytes.extend_from_slice(&G2Affine::GENERATOR.to_bytes());
    bytes.extend_from_slice(&g2_tau.to_bytes());
    for p in &g1 {
        bytes.extend_from_slice(&p.to_bytes());
    }
    let thread: String = format!("{:?}", std::thread::current().id())
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let dir = std::env::temp_dir().join(format!("apogee-logup-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let path = dir.join(format!("toy-{power}-{thread}.srs"));
    std::fs::write(&path, &bytes).expect("writing the toy archive");
    let srs = srs::Srs::load(&path).expect("the toy archive loads");
    std::fs::remove_file(&path).ok();
    srs
}

// ---------------------------------------------------------------------------
// Acceptance 4: S14's future read, now through the timestamp channel
// ---------------------------------------------------------------------------

/// Acceptance 4. S14's acceptance 4 attack, rerun here: two `rs1` queries that
/// read the same value at the same register, with their read timestamps
/// swapped. The read tuples are a permutation of themselves, so the memory
/// multiset still balances, and no gate is broken — `rs1_writes_back` sees the
/// same values — so at S14 only the native evaluator saw it. Now the later of
/// the two reads a timestamp after its own write, its gap is negative, and the
/// timestamp channel refuses it: the tuple is a value `[0, 2^19)` does not
/// hold, the multiplicities cannot even be recounted over it, and the channel's
/// root is not `(0, nonzero)`.
///
/// S14 swapped two reads of `x0`, which is the case where the values match by
/// construction. `JUMP_BRANCH_SLT` makes no `rs1` query on `x0` in fib — a
/// `jal` reads no source register at all — so the pair is found by its
/// property instead of by its register.
#[test]
#[ignore = "2^20 rows: one forward pass holds 4.63 GB of inner cells"]
fn s14s_future_read_now_fails_the_timestamp_channel() {
    let toy = toy();
    let a = &toy.shard.artifact;
    let cell = |name: &str, row: usize| toy.shard.base.get(at(a, name)).expect("a column").get(row);
    let read_ts = at(a, "rs1_read_ts");

    // Two live `rs1` queries at one register reading one value, at different
    // timestamps: swapping those permutes the read tuples and nothing else.
    let live: Vec<usize> = (0..toy.live)
        .filter(|y| cell("rs1_mask", *y) == Fr::ONE)
        .collect();
    let mut pair = None;
    for (i, &early) in live.iter().enumerate() {
        for &late in &live[i + 1..] {
            let same = cell("rs1_addr", early) == cell("rs1_addr", late)
                && cell("rs1_read_value", early) == cell("rs1_read_value", late);
            if same && cell("rs1_read_ts", early) != cell("rs1_read_ts", late) {
                pair = Some((early, late));
                break;
            }
        }
        if pair.is_some() {
            break;
        }
    }
    let (early, late) = pair.expect("fib reads one register twice at one value");

    let forged = with_cells(
        &toy.shard,
        &[
            (read_ts, early, cell("rs1_read_ts", late)),
            (read_ts, late, cell("rs1_read_ts", early)),
        ],
    );
    let values = forwarded_shard(&forged);
    // Every gate still holds: the swap breaks no relation.
    assert_eq!(gkr::self_check(a, &values, &forged.challenges), Ok(()));

    // The gap the earlier row now carries is not a value the table holds, so
    // the honest prover cannot even count it.
    let columns = columns_of(&forged);
    let recount = build_multiplicities(a, &columns, &toy.specs);
    assert!(
        recount.is_err(),
        "a negative gap is no row of [0, 2^19): {:?}",
        recount.map(|_| ())
    );

    // With the honest counts, the timestamp channel does not hold.
    let forged_toy = reshard(&toy, forged);
    let (sums, roots) = sums(&forged_toy, &values);
    let timestamp = channel_at(&sums, lookup_channel::TIMESTAMP);
    assert!(
        !sums[timestamp].unmatched.is_empty(),
        "the negative gap is unmatched"
    );
    assert_ne!(sums[timestamp].num, Fr::ZERO);
    assert!(!channel_holds(roots[timestamp]), "the root refuses it");
    assert_eq!(
        check_channel_roots(&roots, &sums),
        Ok(()),
        "and it is the root the circuit proved"
    );

    // A prover who claims the honest root instead is refused by `verify`.
    assert_eq!(
        verify_claiming(
            &forged_toy,
            &values,
            &[(timestamp, Fr::ZERO, roots[timestamp].1)]
        ),
        Err(gkr::GkrError::LayerInconsistency {
            layer: a.depth() - 1
        }),
        "a forged output claim, refused at the top transition"
    );
}

// ---------------------------------------------------------------------------
// Acceptance 6: the gated keys
// ---------------------------------------------------------------------------

/// Acceptance 6, all three cases of the gated-key convention.
///
/// 1. A row whose flag is 0 contributes exactly the neutral entry whatever its
///    key columns hold: garbage written into `and_a`, `and_b` and `and_c` on
///    such a row leaves every channel root where it was.
/// 2. Tampering a flag = 1 row's key fails: the tuple is no row of the table.
/// 3. The table's real entry `(0, 0, 0)` and the `ZeroEntry` are distinguished,
///    which is the `+ 1` offset: a genuine lookup of `a = b = 0` credits the
///    AND table's own row, and a switched-off row credits row 0.
#[test]
#[ignore = "2^20 rows: one forward pass holds 4.63 GB of inner cells"]
fn the_gated_key_convention_holds_in_all_three_cases() {
    let toy = toy();
    let a = &toy.shard.artifact;
    let honest = forwarded_shard(&toy.shard);
    let (_, honest_roots) = sums(&toy, &honest);
    assert!(honest_roots.iter().all(|r| channel_holds(*r)));

    // 1. Garbage under a flag of 0.
    let off = toy.live;
    assert_eq!(
        toy.shard
            .base
            .get(at(a, "and_on"))
            .expect("a column")
            .get(off),
        Fr::ZERO,
        "row {off} is a padding row, its flag off"
    );
    let garbage = with_cells(
        &toy.shard,
        &[
            (at(a, "and_a"), off, Fr::from_u64(0xdead)),
            (at(a, "and_b"), off, Fr::from_u64(0xbeef)),
            (at(a, "and_c"), off, Fr::from_u64(0x1234)),
        ],
    );
    let values = forwarded_shard(&garbage);
    let (_, roots) = sums(&reshard(&toy, garbage), &values);
    assert_eq!(
        roots, honest_roots,
        "a switched-off row contributes the neutral entry whatever it holds"
    );

    // 2. A flag = 1 row's key moved.
    let live = live_row(&toy, "and_on");
    let forged = with_cells(&toy.shard, &[(at(a, "and_a"), live, Fr::from_u64(0x1ff))]);
    let values = forwarded_shard(&forged);
    let forged_toy = reshard(&toy, forged);
    let (sums, roots) = sums(&forged_toy, &values);
    let generic = channel_at(&sums, lookup_channel::GENERIC);
    assert_eq!(
        sums[generic].unmatched,
        vec![(live, "and_lookup".to_string())],
        "the moved key is no row of the table"
    );
    assert!(!channel_holds(roots[generic]));

    // 3. The `+ 1` offset. A genuine `0 AND 0 = 0` credits the AND table's own
    // row, which is row 1; the switched-off rows credit row 0, the ZeroEntry.
    let zeroed = with_cells(
        &toy.shard,
        &[
            (at(a, "and_a"), live, Fr::ZERO),
            (at(a, "and_b"), live, Fr::ZERO),
            (at(a, "and_c"), live, Fr::ZERO),
        ],
    );
    let counts = build_multiplicities(a, &columns_of(&zeroed), &toy.specs)
        .expect("a genuine entry is countable");
    let (_, generic_counts) = &counts[channel_at_spec(&toy.specs, lookup_channel::GENERIC)];
    assert_ne!(
        generic_counts.get(1),
        Fr::ZERO,
        "the AND entry (0, 0, 0) is the table's row 1, not its row 0"
    );
    assert_ne!(
        generic_counts.get(0),
        Fr::ZERO,
        "and the ZeroEntry at row 0 answers every switched-off row"
    );
}

/// The control for the precondition of `docs/spec/lookup.md` §4: the `+ 1`
/// offset keeps every real **table entry** off the neutral tuple, and that is
/// all it does. A row whose selector is 1 and whose key expression evaluates to
/// `−1` gates to `1·(−1 + 1) = 0`, and with its other columns 0 the whole tuple
/// is the `ZeroEntry` — a table row. The channel balances, every check passes,
/// and the row has looked up the neutral entry instead of a real one.
///
/// The same unbounded key reaches the **other table** too: the AND lookup's key
/// `and_a + AND_BASE + 1` is `SIGN_BASE + h + 1` at `and_a = SIGN_BASE + h`, so
/// an unbounded `and_a` answers an AND claim with a `U16GetSign` row. The
/// tables' key ranges are disjoint; the keys a row can *produce* are not.
///
/// So a family reading a value out of a table channel must bound the key it
/// looks up into its own table's range; the channel cannot. The toy leaves
/// `sign_h` and `and_a` unbounded on purpose — it is a toy for the channels, not
/// a family — and S17 and S18 own the bounds.
#[test]
#[ignore = "2^20 rows: one forward pass holds 4.63 GB of inner cells"]
fn an_unbounded_key_can_reach_the_neutral_entry() {
    let toy = toy();
    let a = &toy.shard.artifact;
    let live = live_row(&toy, "sign_on");

    // `and_a = SIGN_BASE + h` with `h = 0x8001`: the AND tuple is
    // (SIGN_BASE + h + 1, h >> 15, 0), the U16GetSign row for h. The row has
    // "proved" `and_a AND 1 = 0`, which is false.
    let h = 0x8001u64;
    let cross = with_cells(
        &toy.shard,
        &[
            (at(a, "and_a"), live, Fr::from_u64(SIGN_BASE as u64 + h)),
            (at(a, "and_b"), live, Fr::from_u64(h >> 15)),
            (at(a, "and_c"), live, Fr::ZERO),
        ],
    );
    let counted = build_multiplicities(a, &columns_of(&cross), &toy.specs)
        .expect("the AND tuple is a U16GetSign row");
    assert_eq!(counted.len(), 4, "every channel still counts");

    // `sign_h = −(SIGN_BASE + 1)` and `sign_s = 0`: the gated tuple is
    // (0, 0, 0), the ZeroEntry at the packed table's row 0.
    let forged = with_cells(
        &toy.shard,
        &[
            (at(a, "sign_h"), live, -Fr::from_u64(SIGN_BASE as u64 + 1)),
            (at(a, "sign_s"), live, Fr::ZERO),
        ],
    );
    let values = forwarded_shard(&forged);
    assert_eq!(gkr::self_check(a, &values, &forged.challenges), Ok(()));

    // The prover can even recount its multiplicities over it: the tuple is a
    // table row, so it counts on row 0 beside every switched-off row.
    let counts = build_multiplicities(a, &columns_of(&forged), &toy.specs)
        .expect("the neutral tuple is a table row");
    let mut recounted = forged.clone();
    let mut columns = columns_of(&recounted);
    for (address, column) in counts {
        let at = columns
            .iter()
            .position(|(x, _)| *x == address)
            .expect("a multiplicity column");
        columns[at] = (address, column);
    }
    recounted.base = BaseLayer::new(columns);
    let values = forwarded_shard(&recounted);
    let recounted_toy = reshard(&toy, recounted);
    let (sums, roots) = sums(&recounted_toy, &values);
    let generic = channel_at(&sums, lookup_channel::GENERIC);
    assert_eq!(
        sums[generic].unmatched,
        Vec::new(),
        "the tuple is in the table"
    );
    assert_eq!(sums[generic].num, Fr::ZERO, "and the channel balances");
    assert!(channel_holds(roots[generic]), "so the root accepts it");
    assert_eq!(prove_and_verify(&recounted_toy, &values), Ok(()));
}

// ---------------------------------------------------------------------------
// Acceptance 7: the decoder
// ---------------------------------------------------------------------------

/// Acceptance 7. Honest cycle rows bind to `DecodedTables`, which acceptance 1
/// shows. Here: one decoded output moved, and a packed mask outside the table's
/// domain — the all-zero mask included — each refused by the decoder channel.
///
/// The mask is moved together with the bits that recompose it, so the
/// booleanity and recomposition gates still hold and the lookup is the only
/// thing left to catch it. One-hotness comes from the table's domain and from
/// nothing else, which is exactly what the all-zero case shows: booleanity
/// permits it, and the table does not hold it.
#[test]
#[ignore = "2^20 rows: one forward pass holds 4.63 GB of inner cells"]
fn a_moved_decoded_output_and_an_illegal_mask_each_fail_the_decoder_channel() {
    let toy = toy();
    let a = &toy.shard.artifact;
    let live = live_row(&toy, "pc_mask");
    let mask = at(a, "decoded_mask");
    let held = toy.shard.base.get(mask).expect("a column").get(live);
    assert_ne!(held, Fr::ZERO, "a live row's mask is one-hot, never 0");

    // One decoded output moved: the claimed `rd` for this pc.
    let rd = at(a, "decoded_rd");
    let was = toy.shard.base.get(rd).expect("a column").get(live);
    let moved = with_cells(&toy.shard, &[(rd, live, was + Fr::ONE)]);
    assert_eq!(
        decoder_unmatched(&toy, moved),
        vec![(live, "decode_row".to_string())],
        "a claimed output the table does not pair with this pc"
    );

    // Two masks outside the domain, each with its bits: two bits set at once,
    // and the all-zero mask. Both are twelve-bit values whose bits recompose
    // them and are each boolean, so only the table's domain refuses them —
    // which is the whole point of one packed column.
    for claimed in [Fr::from_u64(0b11), Fr::ZERO] {
        let mut cells = vec![(mask, live, claimed)];
        for k in 0..MASK_BITS {
            let bit = bit_of(claimed, k);
            cells.push((at(a, &format!("kind_{k}")), live, bit));
        }
        let forged = with_cells(&toy.shard, &cells);
        let values = forwarded_shard(&forged);
        // The bits still recompose the mask, and each is still boolean.
        assert_eq!(
            gkr::self_check(a, &values, &forged.challenges),
            Ok(()),
            "mask {claimed:?}: every gate holds"
        );
        assert_eq!(
            decoder_unmatched(&toy, forged),
            vec![(live, "decode_row".to_string())],
            "mask {claimed:?}: the table's domain is what refuses it"
        );
    }
}

// ---------------------------------------------------------------------------
// Acceptance 8: a multiplicity-only tamper
// ---------------------------------------------------------------------------

/// Acceptance 8. Honest values with one multiplicity cell changed: the witness
/// is untouched, every gate holds, the recount names the column and the row, and
/// the channel's root is no longer `(0, nonzero)`.
#[test]
#[ignore = "2^20 rows: one forward pass holds 4.63 GB of inner cells"]
fn one_changed_multiplicity_cell_fails_its_channel() {
    let toy = toy();
    let a = &toy.shard.artifact;
    let column = at(a, "mult_generic");
    let was = toy.shard.base.get(column).expect("a column").get(0);
    let forged = with_cells(&toy.shard, &[(column, 0, was + Fr::ONE)]);
    let values = forwarded_shard(&forged);
    assert_eq!(gkr::self_check(a, &values, &forged.challenges), Ok(()));

    let e =
        trace::check_multiplicities(a, &columns_of(&forged), &toy.specs, &counted(&forged, &toy))
            .expect_err("the recount differs");
    assert!(
        e.contains("channel `generic`'s W[") && e.ends_with("differs at row 0"),
        "{e}"
    );

    let forged_toy = reshard(&toy, forged);
    let (sums, roots) = sums(&forged_toy, &values);
    let generic = channel_at(&sums, lookup_channel::GENERIC);
    assert!(
        sums[generic].unmatched.is_empty(),
        "every tuple is still in the table"
    );
    assert_ne!(sums[generic].num, Fr::ZERO, "the counts no longer balance");
    assert!(!channel_holds(roots[generic]));
    assert_eq!(check_channel_roots(&roots, &sums), Ok(()));
}

// ---------------------------------------------------------------------------
// Acceptance 12: booleanity of the extracted bits
// ---------------------------------------------------------------------------

/// Acceptance 12. Every bit the circuit extracts from the packed mask carries
/// `x − x·x = 0`, and a witness that is not 0 or 1 breaks it: the self-check
/// names the gate, and the proof is rejected at gate list 0.
///
/// The tamper is chosen so that `x − x·x` is the **only** thing that refuses
/// it. `kind_0 := 2` alone would also break the recomposition gate
/// `Σ 2^k·kind_k − decoded_mask`, and the test would then pass with the
/// booleanity gates deleted from the artifact. So the mask moves with the bits:
/// `kind_0 := 2`, every other bit 0, `decoded_mask := 2`. Recomposition holds
/// (`2·1 = 2`), `0b10` is a legal one-hot mask, so the decoder channel has no
/// quarrel with the row either — and only booleanity is left.
#[test]
#[ignore = "2^20 rows: one forward pass holds 4.63 GB of inner cells"]
fn a_non_boolean_extracted_bit_is_refused_by_its_gate() {
    let toy = toy();
    let a = &toy.shard.artifact;
    // Each of the twelve has its own gate, named for it.
    for k in 0..MASK_BITS {
        let name = format!("kind_{k}_boolean");
        assert!(
            a.relations.iter().any(|r| r.name == name),
            "the artifact carries `{name}`"
        );
    }
    let live = live_row(&toy, "pc_mask");
    let two = Fr::from_u64(2);
    let mut cells = vec![
        (at(a, "decoded_mask"), live, two),
        (at(a, "kind_0"), live, two),
    ];
    for k in 1..MASK_BITS {
        cells.push((at(a, &format!("kind_{k}")), live, Fr::ZERO));
    }
    let forged = with_cells(&toy.shard, &cells);
    let values = forwarded_shard(&forged);
    let broken = gkr::self_check(a, &values, &forged.challenges).expect_err("a non-boolean bit");
    assert_eq!(broken.row, live);
    assert_eq!(
        broken.relation, "kind_0_boolean",
        "the recomposition still holds, so booleanity is the only gate left"
    );
    assert_eq!(
        prove_and_verify(&reshard(&toy, forged), &values),
        Err(gkr::GkrError::LayerInconsistency { layer: 0 }),
        "an enforcing gate of gate list 0"
    );
}

// ---------------------------------------------------------------------------
// The shared tamper helpers
// ---------------------------------------------------------------------------

/// `toy` with `shard` in place of its own: a tampered base, the same specs, the
/// same live count and the same seeded transcript. The seeding binds the honest
/// columns, which is exactly what a prover who tampers after committing has.
fn reshard(toy: &Toy, shard: Shard) -> Toy {
    Toy {
        shard,
        specs: toy.specs.clone(),
        live: toy.live,
        seeded: toy.seeded,
    }
}

/// A shard's committed columns, by address.
fn columns_of(shard: &Shard) -> Vec<(PolyAddress, MultilinearPoly)> {
    shard
        .artifact
        .committed()
        .into_iter()
        .map(|address| (address, shard.base.get(address).expect("a column").clone()))
        .collect()
}

/// A shard's multiplicity columns as `check_multiplicities` takes them.
fn counted(shard: &Shard, toy: &Toy) -> Vec<(PolyAddress, MultilinearPoly)> {
    toy.specs
        .iter()
        .map(|spec| {
            (
                spec.multiplicity,
                shard.base.get(spec.multiplicity).expect("a column").clone(),
            )
        })
        .collect()
}

/// Channel `channel`'s position in a `ChannelSum` list.
fn channel_at(sums: &[ChannelSum], channel: u32) -> usize {
    sums.iter()
        .position(|s| s.channel == channel)
        .unwrap_or_else(|| panic!("no channel {channel}"))
}

/// Channel `channel`'s position in a spec list.
fn channel_at_spec(specs: &[ChannelSpec], channel: u32) -> usize {
    specs
        .iter()
        .position(|s| s.channel == channel)
        .unwrap_or_else(|| panic!("no channel {channel}"))
}

/// A live row on which `flag` is 1.
fn live_row(toy: &Toy, flag: &str) -> usize {
    let column = toy
        .shard
        .base
        .get(at(&toy.shard.artifact, flag))
        .expect("a column");
    (0..toy.live)
        .find(|y| column.get(*y) == Fr::ONE)
        .unwrap_or_else(|| panic!("no row has {flag} = 1"))
}

/// Bit `k` of a field element that is a small integer.
fn bit_of(v: Fr, k: usize) -> Fr {
    Fr::from_u64(u64::from((small(v) >> k) & 1))
}

/// The decoder channel's unmatched rows on a forged shard.
fn decoder_unmatched(toy: &Toy, forged: Shard) -> Vec<(usize, String)> {
    let values = forwarded_shard(&forged);
    let forged_toy = reshard(toy, forged);
    let (sums, roots) = sums(&forged_toy, &values);
    let decoder = channel_at(&sums, lookup_channel::DECODER);
    assert!(!channel_holds(roots[decoder]), "the root refuses it");
    sums[decoder].unmatched.clone()
}

/// Prove `values` and verify the proof, both transcripts restored from the
/// shard's seeded state: every committed column bound by its commitment, and
/// `g` and `β` drawn, before a single round message.
fn prove_and_verify(toy: &Toy, values: &LayerValues) -> Result<(), gkr::GkrError> {
    verify_claiming(toy, values, &[])
}

/// [`prove_and_verify`] with the channel pairs of `claimed` replacing the
/// circuit's own in the output claims, so a prover claiming a root it did not
/// compute is refused by the engine rather than by the root check.
fn verify_claiming(
    toy: &Toy,
    values: &LayerValues,
    claimed: &[(usize, Fr, Fr)],
) -> Result<(), gkr::GkrError> {
    let shard = &toy.shard;
    let a = &shard.artifact;
    let bound = || Transcript::restore(&toy.seeded);
    let proof = gkr::prove(a, values, &shard.challenges, &mut bound());
    let top = values.layers.last().expect("a top layer");
    let mut tables: Vec<MultilinearPoly> = a
        .outputs
        .iter()
        .map(|out| match *out {
            PolyAddress::Inner { offset, .. } => top[offset as usize].clone(),
            other => panic!("an output is an inner address, not {other}"),
        })
        .collect();
    // The channel pairs are the outputs after the two memory roots.
    for (i, num, den) in claimed {
        tables[2 + 2 * i] = MultilinearPoly::new(PolyBacking::Fr(vec![*num]));
        tables[2 + 2 * i + 1] = MultilinearPoly::new(PolyBacking::Fr(vec![*den]));
    }
    gkr::verify(
        a,
        &proof,
        &gkr::OutputClaims { tables },
        &shard.challenges,
        &mut bound(),
    )
    .map(|_| ())
}
