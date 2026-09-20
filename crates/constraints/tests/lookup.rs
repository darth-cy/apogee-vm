//! The LogUp channels as data: the committed toy pinned, the discharge rule and
//! its negative controls (acceptance 11), the channel construction refusals,
//! the copower-pairing assertion, and the wire form of the new gate shape and
//! the new virtual kinds.
//!
//! Every test here builds artifacts, never columns, so the toy's `2^20` rows
//! are a number and nothing is materialized. `crates/checker/tests/logup.rs` is
//! where the columns are filled and the circuit is proved.

mod common;

use common::fixture_bytes;
use constants::{challenge_slot, family, lookup_channel};
use constraints::lookup::{
    beta_power, check_copowers, check_discharge, range_table, row_denominator, table_denominator,
    ChannelSpec,
};
use constraints::memory::{frame_queries, frame_with_channels_artifact, FamilySpec};
use constraints::{CircuitArtifact, Coeff, GateDef, LookupExpr, PolyAddress, VirtualKind};
use field::Fr;

/// `tools/kat-gen/src/lookup.rs`'s output.
const TOY: &str = "lookup_toy.bin";
const TOY_SHA256: &str = "abab86f0c6cda7d087de044f632f7764bc0cf8db4bdb95ebe229a4f61a85da8b";

/// The toy's family, height and mask width, as that file fixes them.
const FAMILY: u32 = family::JUMP_BRANCH_SLT;
const VARS: u32 = 20;
const MASK_BITS: usize = 12;
/// One `<q>_gap_hi` per query, then the x0 gadget's three.
const FRAME_WITNESS: u32 = 4 + 3;

fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

fn w(i: u32) -> PolyAddress {
    PolyAddress::Witness(i)
}

fn column(x: PolyAddress) -> GateDef {
    GateDef::Linear {
        terms: vec![(lit(1), x)],
        constant: lit(0),
    }
}

fn toy() -> CircuitArtifact {
    let bytes = fixture_bytes(TOY, TOY_SHA256);
    CircuitArtifact::from_bytes(&bytes).expect("the toy decodes")
}

/// The committed toy is a circuit: it validates, keeps the memory rules, and
/// every one of its lookups is discharged by exactly one gate-list-0 column.
/// Its shape is the one `tools/kat-gen/src/lookup.rs` describes: four channels,
/// the memory roots first in the output map and each channel's `(num, den)`
/// pair after them, in channel order.
#[test]
fn the_committed_toy_is_a_circuit_that_discharges_every_lookup() {
    let a = toy();
    assert_eq!(a.trace_vars, VARS);
    assert_eq!(a.validate(), Ok(()));
    assert_eq!(constraints::memory::check_memory(&a), Ok(()));
    assert_eq!(check_discharge(&a, &[]), Ok(()));

    // Two memory roots, then one pair per channel in channel order.
    assert_eq!(a.outputs.len(), 2 + 2 * lookup_channel::COUNT as usize);
    let name = |address: PolyAddress| {
        a.scratch
            .iter()
            .find(|s| s.address == address)
            .map(|s| s.name.as_str())
            .expect("an output is a scratch slot")
    };
    let mut expected = vec!["read_root".to_string(), "write_root".to_string()];
    for channel in lookup_channel::NAMES {
        expected.push(format!("{channel}_num_root"));
        expected.push(format!("{channel}_den_root"));
    }
    let got: Vec<String> = a.outputs.iter().map(|o| name(*o).to_string()).collect();
    assert_eq!(got, expected);

    // The frame's own obligations come first, then the family spec's.
    let channels: Vec<u32> = a.lookups.iter().map(|l| l.channel).collect();
    assert_eq!(
        channels,
        vec![lookup_channel::TIMESTAMP; 8]
            .into_iter()
            .chain([lookup_channel::RANGE16; 2])
            .chain([lookup_channel::GENERIC; 2])
            .chain([lookup_channel::DECODER])
            .collect::<Vec<_>>()
    );
    // Every selector is held to booleanity, which `validate` refuses without.
    assert!(a
        .lookups
        .iter()
        .all(|l| matches!(l.selector, PolyAddress::Memory(_) | PolyAddress::Witness(_))));
}

// ---------------------------------------------------------------------------
// Acceptance 11: the discharge cross-check's negative controls
// ---------------------------------------------------------------------------

/// Acceptance 11. An obligation nothing discharges, and one two columns
/// discharge, are each refused naming the lookup or the column. The honest twin
/// beside them is the committed toy.
#[test]
fn an_unconsumed_and_a_doubly_consumed_obligation_each_fail_the_check() {
    assert_eq!(check_discharge(&toy(), &[]), Ok(()));

    // Unconsumed: a lookup the circuit's leaves do not carry.
    let mut unconsumed = toy();
    let mut extra = unconsumed.lookups[0].clone();
    extra.name = "gap_hi_pc_again".to_string();
    extra.tuple = vec![column(w(1))];
    unconsumed.lookups.push(extra);
    assert_eq!(
        check_discharge(&unconsumed, &[]),
        Err(
            "lookup discharge: lookup `gap_hi_pc_again` is the denominator of 0 gate-list-0 \
             columns; exactly one discharges it"
                .to_string()
        )
    );

    // Doubly consumed: one column is two lookups' denominator, which is what a
    // list that names an obligation twice looks like from the artifact.
    let mut doubled = toy();
    let mut twin = doubled.lookups[0].clone();
    twin.name = "gap_hi_pc_twin".to_string();
    doubled.lookups.push(twin);
    let e = check_discharge(&doubled, &[]).expect_err("a doubly-consumed obligation");
    assert!(
        e.starts_with("lookup discharge: column `gap_hi_pc_den` is the denominator of 2 lookups"),
        "{e}"
    );
}

/// One lookup that **two columns of its own channel's tree** discharge is
/// refused. The timestamp tree adds that fraction twice while the multiplicity
/// column counts it once, so the honest prover cannot balance — and every other
/// half of the rule is blind to it: the numerator is where it should be, the
/// column is in the right cone, and no column is two lookups' denominator, so
/// only the count itself catches it.
#[test]
fn two_columns_of_one_channel_discharging_one_lookup_are_refused() {
    let specs = toy_specs();
    let mut a = toy();
    let slot = |a: &CircuitArtifact, name: &str| {
        a.scratch
            .iter()
            .position(|s| s.name == name)
            .unwrap_or_else(|| panic!("the toy has no column `{name}`"))
    };
    // `gap_lo_pc_den` rewritten as a second copy of `gap_hi_pc_den`, relation
    // and all, with its own obligation dropped from the list so that nothing is
    // left unconsumed.
    let (hi, lo) = (slot(&a, "gap_hi_pc_den"), slot(&a, "gap_lo_pc_den"));
    let gate = a.layers[0].producing[hi].gate.clone();
    let r = a.layers[0].producing[lo].relation as usize;
    a.layers[0].producing[lo].gate = gate.clone();
    a.relations[r].gate = gate;
    a.lookups.retain(|l| l.name != "gap_lo_pc");
    assert_eq!(a.validate(), Ok(()), "still a lawful circuit");

    let e = check_discharge(&a, &specs).expect_err("two columns discharge one lookup");
    assert!(
        e.contains(
            "lookup `gap_hi_pc` is the denominator of 2 columns of channel `timestamp`'s \
             fraction tree"
        ),
        "{e}"
    );
}

/// The count is per channel, not per circuit. The two range channels gate and
/// neutralize identically (§4), so a `timestamp` and a `range16` obligation over
/// one selector and one expression have **byte-identical** denominator gates:
/// counting matches over the whole gate list would see two columns for each and
/// refuse a circuit in which both are discharged exactly once. Bounding one
/// expression in two channels is ordinary — a value under `2^16` is also under
/// `2^19` — so the rule counts inside each lookup's own channel's cone.
#[test]
fn one_expression_bounded_in_two_range_channels_is_discharged_once_in_each() {
    let a = build(VARS, |e| {
        e.witness.push("mult_range16".to_string());
        e.virtuals
            .push((VirtualKind::Range16, "range16".to_string()));
        e.lookups.push(LookupExpr {
            name: "value_range16".to_string(),
            channel: lookup_channel::RANGE16,
            selector: w(FLAG),
            tuple: vec![column(w(VALUE))],
        });
        e.channels.push(ChannelSpec {
            channel: lookup_channel::RANGE16,
            table: vec![PolyAddress::Virtual(VirtualKind::Range16)],
            multiplicity: w(MULT_GENERIC + 1),
        });
    });
    // The construction itself runs the rule, so reaching this line is the
    // assertion; what it is an assertion *about* is the collision below.
    let two: Vec<&LookupExpr> = a
        .lookups
        .iter()
        .filter(|l| l.name == "value_range" || l.name == "value_range16")
        .collect();
    assert_eq!(two.len(), 2);
    assert_ne!(two[0].channel, two[1].channel);
    assert_eq!(
        row_denominator(two[0]),
        row_denominator(two[1]),
        "the two channels' denominator gates are the same gate"
    );
}

/// A lookup whose fraction numerator is not 1 contributes nothing: its row's
/// term is `0/(E_l + g)`, so the obligation is silently dropped while its
/// denominator still sits where every other check looks. The same for a
/// channel's table fraction, whose numerator is `−mult`.
#[test]
fn a_fraction_numerator_moved_off_its_leaf_drops_the_obligation() {
    let specs = toy_specs();
    let mut a = toy();
    assert_eq!(check_discharge(&a, &specs), Ok(()));

    let at = |a: &CircuitArtifact, name: &str| {
        a.scratch
            .iter()
            .position(|s| s.name == name)
            .unwrap_or_else(|| panic!("the toy has no column `{name}`"))
    };
    // The obligation's numerator, in the gate and its relation alike.
    let zero = GateDef::Linear {
        terms: vec![],
        constant: lit(0),
    };
    let j = at(&a, "gap_hi_pc_num");
    let r = a.layers[0].producing[j].relation as usize;
    a.layers[0].producing[j].gate = zero.clone();
    a.relations[r].gate = zero.clone();
    assert_eq!(a.validate(), Ok(()), "still a lawful circuit");
    let e = check_discharge(&a, &specs).expect_err("a numerator moved to 0");
    assert!(
        e.contains("lookup `gap_hi_pc`'s fraction has no numerator of 1"),
        "{e}"
    );

    // And the table fraction's numerator, which is `−mult`.
    let mut b = toy();
    let j = at(&b, "timestamp_table_num");
    let r = b.layers[0].producing[j].relation as usize;
    b.layers[0].producing[j].gate = zero.clone();
    b.relations[r].gate = zero;
    assert_eq!(b.validate(), Ok(()));
    let e = check_discharge(&b, &specs).expect_err("a table numerator moved to 0");
    assert!(
        e.contains("channel `timestamp`'s table fraction has no numerator"),
        "{e}"
    );
}

/// A lookup discharged by a column in **another** channel's fraction tree is
/// summed against the wrong table, and the channel half of the rule refuses it.
/// Two leaves of the toy swapped — a `range16` obligation's denominator for a
/// `timestamp` one's, relations and all — is still a lawful circuit whose every
/// lookup is the denominator of exactly one column; only the cone walk sees
/// that the 16-bit obligation is now summed against `[0, 2^19)`.
#[test]
fn an_obligation_discharged_against_another_channels_table_is_refused() {
    let specs = toy_specs();
    let a = toy();
    assert_eq!(check_discharge(&a, &specs), Ok(()));

    let at = |name: &str| {
        a.scratch
            .iter()
            .position(|s| s.name == name)
            .unwrap_or_else(|| panic!("the toy has no column `{name}`"))
    };
    let (range16, timestamp) = (at("word_hi_range_den"), at("gap_hi_pc_den"));
    let mut swapped = a.clone();
    swap_leaf_gates(&mut swapped, range16, timestamp);

    assert_eq!(swapped.validate(), Ok(()), "still a lawful circuit");
    // The column half alone accepts it: every lookup is still exactly one
    // column's denominator, the columns merely changed trees.
    assert_eq!(check_discharge(&swapped, &[]), Ok(()));
    let e = check_discharge(&swapped, &specs).expect_err("a misrouted obligation");
    assert!(
        e.contains("is discharged by a column outside channel")
            && e.contains("so it is summed against another table"),
        "{e}"
    );
}

/// A channel's **table fraction** in another channel's tree is refused, for the
/// reason a misrouted obligation is. The toy's `timestamp` and `range16` table
/// fractions swapped — each channel's `(−mult, T + g)` pair put where the
/// other's belongs, numerator and denominator together — leaves the 19-bit tree
/// subtracting a count of 16-bit rows from a sum of 19-bit ones, and the 16-bit
/// tree the reverse. Neither channel then proves anything about its own table,
/// and the honest prover cannot balance either tree.
///
/// Every other half of the rule is blind to it. Each table denominator is still
/// exactly one column of the gate list, each still has its own `−mult`
/// numerator directly before it, every lookup is still discharged once inside
/// its own cone, and no column is two lookups'. Only walking down from the
/// channel's own root pair sees which tree the fraction ended up in — which is
/// why the count runs inside the cone and not over the whole list.
#[test]
fn two_channels_table_fractions_swapped_between_their_trees_are_refused() {
    let specs = toy_specs();
    let a = toy();
    assert_eq!(check_discharge(&a, &specs), Ok(()));

    let at = |name: &str| {
        a.scratch
            .iter()
            .position(|s| s.name == name)
            .unwrap_or_else(|| panic!("the toy has no column `{name}`"))
    };
    let mut swapped = a.clone();
    swap_leaf_gates(
        &mut swapped,
        at("timestamp_table_num"),
        at("range16_table_num"),
    );
    swap_leaf_gates(
        &mut swapped,
        at("timestamp_table_den"),
        at("range16_table_den"),
    );
    assert_eq!(swapped.validate(), Ok(()), "still a lawful circuit");

    // What the swap did NOT break, stated rather than assumed: each channel's
    // table denominator is one column of the list and carries its numerator,
    // so a rule that matched over the whole list would find both and accept.
    for spec in &specs[..2] {
        let den = table_denominator(spec);
        let found: Vec<usize> = (0..swapped.layers[0].producing.len())
            .filter(|&j| swapped.layers[0].producing[j].gate == den)
            .collect();
        assert_eq!(found.len(), 1, "one column still compresses this table");
        assert_eq!(
            swapped.layers[0].producing[found[0] - 1].gate,
            GateDef::Linear {
                terms: vec![(Coeff::Literal(Fr::MINUS_ONE), spec.multiplicity)],
                constant: lit(0),
            },
            "and its `−mult` numerator is still directly before it"
        );
    }
    // And the column half alone accepts it: no lookup's denominator moved.
    assert_eq!(check_discharge(&swapped, &[]), Ok(()));

    let e = check_discharge(&swapped, &specs).expect_err("swapped table fractions");
    assert!(
        e.contains(
            "channel `timestamp`'s table fraction is a column outside its own fraction tree"
        ),
        "{e}"
    );
}

/// Swap what two gate-list-0 columns compute, in the producing entry and in the
/// relation it encodes. Names, addresses and outputs stay where they are: the
/// column keeps its identity in the artifact and changes only its gate, which
/// is what a builder that wired a leaf to the wrong tree produces. Nothing here
/// matches by name — `check_discharge` reads normalized expansions — so the
/// names are left alone deliberately.
fn swap_leaf_gates(a: &mut CircuitArtifact, j: usize, k: usize) {
    let (rj, rk) = (
        a.layers[0].producing[j].relation as usize,
        a.layers[0].producing[k].relation as usize,
    );
    let gj = a.layers[0].producing[j].gate.clone();
    let gk = a.layers[0].producing[k].gate.clone();
    a.layers[0].producing[j].gate = gk.clone();
    a.layers[0].producing[k].gate = gj.clone();
    a.relations[rj].gate = gk;
    a.relations[rk].gate = gj;
}

/// The toy's four channels, as `tools/kat-gen/src/lookup.rs` declares them.
fn toy_specs() -> Vec<ChannelSpec> {
    let a = toy();
    let table = |names: &[&str]| -> Vec<PolyAddress> { names.iter().map(|n| at(&a, n)).collect() };
    let mult = |c: u32| at(&a, &format!("mult_{}", lookup_channel::NAMES[c as usize]));
    vec![
        ChannelSpec {
            channel: lookup_channel::TIMESTAMP,
            table: vec![PolyAddress::Virtual(VirtualKind::Range19)],
            multiplicity: mult(lookup_channel::TIMESTAMP),
        },
        ChannelSpec {
            channel: lookup_channel::RANGE16,
            table: vec![PolyAddress::Virtual(VirtualKind::Range16)],
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

// ---------------------------------------------------------------------------
// The channel construction rules
// ---------------------------------------------------------------------------

/// A minimal `FamilySpec` beside the frame: a timestamp obligation over one
/// witness column, and a two-column generic lookup over a committed table.
/// Each refusal below breaks one rule of it.
///
/// The witness layout is `value, flag, gen_a, gen_b`, then the two multiplicity
/// columns last, as S15 must-be-exact 5 requires.
const VALUE: u32 = FRAME_WITNESS;
const FLAG: u32 = FRAME_WITNESS + 1;
const GEN_A: u32 = FRAME_WITNESS + 2;
const GEN_B: u32 = FRAME_WITNESS + 3;
const MULT_TIMESTAMP: u32 = FRAME_WITNESS + 4;
const MULT_GENERIC: u32 = FRAME_WITNESS + 5;

fn family_spec(edit: fn(&mut FamilySpec)) -> FamilySpec {
    let boolean = |x: PolyAddress| GateDef::Quadratic {
        constant: lit(0),
        linear: vec![(lit(1), x)],
        products: vec![(Coeff::Literal(Fr::MINUS_ONE), x, x)],
    };
    let mut e = FamilySpec {
        witness: [
            "value",
            "flag",
            "gen_a",
            "gen_b",
            "mult_timestamp",
            "mult_generic",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
        setup: vec!["gen_key".to_string(), "gen_v1".to_string()],
        virtuals: vec![(VirtualKind::Range19, "range19".to_string())],
        enforcing: vec![("flag_boolean".to_string(), boolean(w(FLAG)))],
        lookups: vec![
            LookupExpr {
                name: "value_range".to_string(),
                channel: lookup_channel::TIMESTAMP,
                selector: w(FLAG),
                tuple: vec![column(w(VALUE))],
            },
            LookupExpr {
                name: "gen_lookup".to_string(),
                channel: lookup_channel::GENERIC,
                selector: w(FLAG),
                tuple: vec![column(w(GEN_A)), column(w(GEN_B))],
            },
        ],
        channels: vec![
            ChannelSpec {
                channel: lookup_channel::TIMESTAMP,
                table: vec![PolyAddress::Virtual(VirtualKind::Range19)],
                multiplicity: w(MULT_TIMESTAMP),
            },
            ChannelSpec {
                channel: lookup_channel::GENERIC,
                table: vec![PolyAddress::Setup(0), PolyAddress::Setup(1)],
                multiplicity: w(MULT_GENERIC),
            },
        ],
    };
    edit(&mut e);
    e
}

fn build(vars: u32, edit: fn(&mut FamilySpec)) -> CircuitArtifact {
    frame_with_channels_artifact(frame_queries(FAMILY), vars, family_spec(edit))
}

/// The control: the minimal family spec builds a circuit at the toy's height, with a
/// range channel and a table channel side by side.
#[test]
fn the_minimal_family_spec_builds_a_circuit() {
    let a = build(VARS, |_| {});
    assert_eq!(a.validate(), Ok(()));
    assert_eq!(check_discharge(&a, &[]), Ok(()));
    assert_eq!(constraints::memory::check_memory(&a), Ok(()));
}

/// A range channel's table holds `2^trace_vars` values at most, so a circuit
/// narrower than the channel's bound cannot carry it. `BITS[TIMESTAMP]` is 19,
/// and the height menu's even entries put every family that carries a gap
/// obligation at `2^20` or above.
#[test]
#[should_panic(expected = "a 19-bit range table needs 19 variables, and this circuit has 18")]
fn a_range_channel_wider_than_its_circuit_is_refused() {
    build(18, |_| {});
}

/// A channel with a table and a multiplicity column but no lookup discharges
/// nothing, and is refused rather than built as a tree over one fraction.
#[test]
#[should_panic(expected = "channel `range16` has a table and a multiplicity column but no lookup")]
fn a_channel_with_no_lookup_is_refused() {
    build(VARS, |e| {
        e.witness.push("mult_range16".to_string());
        e.virtuals
            .push((VirtualKind::Range16, "range16".to_string()));
        e.channels.push(ChannelSpec {
            channel: lookup_channel::RANGE16,
            table: vec![PolyAddress::Virtual(VirtualKind::Range16)],
            multiplicity: w(MULT_GENERIC + 1),
        });
    });
}

/// A lookup naming a channel no spec declares is discharged by nothing, which
/// the discharge rule refuses at construction.
#[test]
#[should_panic(expected = "lookup `gen_lookup` is the denominator of 0 gate-list-0 columns")]
fn a_lookup_whose_channel_no_spec_declares_is_refused() {
    build(VARS, |e| {
        e.channels.pop();
    });
}

/// A caller that declares no channel at all is refused at the entry point,
/// before anything is built. A frame carries its own `2w` gap obligations
/// whatever a caller adds, so an empty channel list is a circuit every
/// obligation of which is undischarged — the one shape where the discharge rule
/// has the most to say and, were it run only for circuits that declare a
/// channel, the one shape it would never be asked of. S14's bare
/// `frame_artifact` is the one artifact that legitimately carries obligations
/// without a channel, and it does not come through here.
#[test]
#[should_panic(expected = "no channel, and a frame's own 8 gap obligations would be discharged")]
fn extra_lookups_with_no_channel_at_all_are_refused() {
    build(VARS, |e| {
        e.channels.clear();
        e.witness.retain(|n| !n.starts_with("mult_"));
        e.setup.clear();
    });
}

/// Every lookup of a channel is as wide as the channel's table: they share one
/// table, and a narrower tuple would compress to a value the table cannot hold.
#[test]
#[should_panic(expected = "has 1 expressions, and channel `generic`'s table has 2 columns")]
fn a_lookup_narrower_than_its_channels_table_is_refused() {
    build(VARS, |e| {
        e.lookups[1].tuple.pop();
    });
}

/// A tuple position above 0 weights its columns by 1 and carries no constant:
/// `β^j·c` is one `Coeff` only when `β^0 = 1` makes it a literal, or when
/// `c = 1` makes it the slot itself. The constructor builds the denominator
/// gate before it validates, so its own assertion is what a caller sees; the
/// test below is the same rule on a **decoded** artifact, where `validate` is.
#[test]
#[should_panic(expected = "expression 1 weights W[10] by a coefficient other than 1")]
fn a_scaled_term_above_tuple_position_zero_is_refused() {
    build(VARS, |e| {
        e.lookups[1].tuple[1] = GateDef::Linear {
            terms: vec![(lit(2), w(GEN_B))],
            constant: lit(0),
        };
    });
}

/// The same rule on the constant, and `validate`'s own refusal of an artifact
/// that reaches it by `from_bytes` rather than by the constructor: the toy with
/// expression 1 of its decoder lookup given a constant is a decodable artifact
/// `validate` refuses, so `check_discharge` — which assumes a validated
/// artifact — is never handed one whose denominator gate does not exist.
#[test]
fn a_constant_above_tuple_position_zero_is_refused_by_validate() {
    let mut a = toy();
    let decoder = a
        .lookups
        .iter()
        .position(|l| l.channel == lookup_channel::DECODER)
        .expect("the toy has a decoder lookup");
    let GateDef::Linear { constant, .. } = &mut a.lookups[decoder].tuple[1] else {
        panic!("a tuple expression is a Linear gate");
    };
    *constant = lit(7);
    let e = a
        .validate()
        .expect_err("a weighted expression above position 0");
    assert_eq!(
        e.to_string(),
        "malformed circuit: lookup `decode_row` weights expression 1 by something other than \
         1, or gives it a constant; only expression 0 may, `β^0` being the literal 1"
    );
    // It still round-trips, which is what makes the rule `validate`'s and not
    // the wire form's.
    assert_eq!(CircuitArtifact::from_bytes(&a.to_bytes()), Ok(a));
}

/// A lookup whose selector gate list 0 does not hold to booleanity is refused
/// by `validate`: LogUp sums `s/(E + g)`, which is the native reading of an
/// obligation only at a boolean `s` (`docs/spec/lookup.md` §2).
#[test]
#[should_panic(expected = "which gate list 0 does not hold to booleanity")]
fn a_selector_without_a_booleanity_gate_is_refused() {
    build(VARS, |e| {
        e.lookups[0].selector = w(VALUE);
    });
}

/// `β`'s powers run out at `MAX_TUPLE` columns, which is where
/// `constants::challenge_slot` stops defining them.
#[test]
#[should_panic(expected = "a lookup tuple has at most 7 columns")]
fn a_tuple_position_past_max_tuple_has_no_beta_power() {
    beta_power(lookup_channel::MAX_TUPLE + 1);
}

/// `β^0` is the literal 1 and every power above it is its own slot, in order.
#[test]
fn the_beta_powers_are_the_literal_one_then_the_slots_in_order() {
    assert_eq!(beta_power(0), lit(1));
    for j in 1..=lookup_channel::MAX_TUPLE - 1 {
        assert_eq!(
            beta_power(j),
            Coeff::Challenge(challenge_slot::LOOKUP_BETA_POWERS[j - 1])
        );
    }
}

/// A range channel's table is the virtual kind its bound names, and a table
/// channel has none.
#[test]
fn each_range_channel_names_its_virtual_table() {
    assert_eq!(
        range_table(lookup_channel::TIMESTAMP),
        Some(VirtualKind::Range19)
    );
    assert_eq!(
        range_table(lookup_channel::RANGE16),
        Some(VirtualKind::Range16)
    );
    assert_eq!(range_table(lookup_channel::GENERIC), None);
    assert_eq!(range_table(lookup_channel::DECODER), None);
    // And the table side is `Σ_j β^j·t_j + g`, the powers in tuple order.
    let spec = ChannelSpec {
        channel: lookup_channel::GENERIC,
        table: vec![
            PolyAddress::Setup(0),
            PolyAddress::Setup(1),
            PolyAddress::Setup(2),
        ],
        multiplicity: w(0),
    };
    let GateDef::Linear { terms, constant } = table_denominator(&spec) else {
        panic!("the table denominator is a Linear gate");
    };
    assert_eq!(constant, Coeff::Challenge(challenge_slot::LOOKUP_G));
    let weights: Vec<Coeff> = terms.iter().map(|(c, _)| *c).collect();
    assert_eq!(weights, (0..3).map(beta_power).collect::<Vec<_>>());
}

// ---------------------------------------------------------------------------
// The copower-pairing assertion
// ---------------------------------------------------------------------------

/// Every copower-scaled column carries a direct range check of its own, under
/// the selector the scaled obligation carries, in either shape
/// `docs/spec/memory.md` §7 gives one: `word_hi` is a halfword bounded by an
/// obligation of its own, and `word` is a 32-bit value bounded by that high
/// chunk and the remainder `word − 2^16·word_hi`. A column with no obligation
/// at all is refused, and so is one whose direct bound sits under a different
/// selector.
///
/// Why the scaled half is not enough: a copower turns `x < p` into
/// `x·p' < 2^32` with `p·p' = 2^32`, and `p'` is a unit in `Fr`, so
/// `x = s·p'^{-1}` sweeps a coset of `2^32` elements almost none of which are
/// small integers. The range check on `s` sees nothing wrong.
///
/// Why the selector is half the check: on a row the direct bound's selector
/// switches off and the scaled one's does not, the direct bound is vacuous and
/// the scaled bound is back to bounding nothing. S17 matched an obligation on
/// its expression alone and left that open; S18 closed it.
#[test]
fn a_copower_scaled_column_needs_its_own_direct_range_check() {
    let a = toy();
    let live = at(&a, "pc_mask");
    assert_eq!(check_copowers(&a, &[]), Ok(()));
    assert_eq!(
        check_copowers(&a, &[(at(&a, "word_hi"), live)]),
        Ok(()),
        "a halfword"
    );
    assert_eq!(
        check_copowers(&a, &[(at(&a, "word"), live), (at(&a, "word_hi"), live)]),
        Ok(()),
        "a 32-bit value under the two-halfword convention"
    );

    // A column with no obligation at all.
    let e = check_copowers(&a, &[(at(&a, "and_a"), live)]).expect_err("and_a is unbounded");
    assert!(
        e.contains("but no range16 obligation under that selector bounds it directly"),
        "{e}"
    );

    // And the remainder alone does not bound the value: with the obligation on
    // the high chunk removed, `word` is no longer directly bounded, because
    // `word − 2^16·word_hi` small says nothing while `word_hi` is free.
    let mut half = a.clone();
    half.lookups.retain(|l| l.name != "word_hi_range");
    assert!(check_copowers(&half, &[(at(&a, "word"), live)]).is_err());
    assert!(check_copowers(&half, &[(at(&a, "word_hi"), live)]).is_err());

    // A shifted bound is not a direct one. `word_hi + 2^15 < 2^16` says nothing
    // about `word_hi`: it admits `word_hi = p − 1`, whose canonical
    // representative is the modulus minus one, which is the very case the whole
    // assertion exists for. So the obligation must carry no constant.
    let mut shifted = a.clone();
    for l in shifted
        .lookups
        .iter_mut()
        .filter(|l| l.name == "word_hi_range")
    {
        let GateDef::Linear { constant, .. } = &mut l.tuple[0] else {
            panic!("a range obligation is one Linear");
        };
        *constant = lit(1 << 15);
    }
    assert!(
        check_copowers(&shifted, &[(at(&a, "word_hi"), live)]).is_err(),
        "`word_hi + 2^15 < 2^16` is not a bound on `word_hi`"
    );

    // The bound is there but under another selector: the pair moves to
    // `and_on`, which is 0 on rows the pc mask is 1 on, so on those rows the
    // direct bound says nothing and the scaled one is alone again. Refused,
    // and the honest selector is accepted beside it.
    let mut elsewhere = a.clone();
    let and_on = at(&a, "and_on");
    for l in elsewhere.lookups.iter_mut() {
        if l.name == "word_hi_range" || l.name == "word_lo_range" {
            l.selector = and_on;
        }
    }
    let e = check_copowers(&elsewhere, &[(at(&a, "word"), live)])
        .expect_err("the direct pair is under another selector");
    assert!(
        e.contains("but no range16 obligation under that selector bounds it directly"),
        "{e}"
    );
    assert_eq!(
        check_copowers(&elsewhere, &[(at(&a, "word"), and_on)]),
        Ok(()),
        "under the selector the pair really carries, it bounds"
    );
}

/// The committed column named `name`.
fn at(a: &CircuitArtifact, name: &str) -> PolyAddress {
    let find = |list: &[String], make: fn(u32) -> PolyAddress| {
        list.iter().position(|n| n == name).map(|i| make(i as u32))
    };
    find(&a.memory, PolyAddress::Memory)
        .or_else(|| find(&a.witness, PolyAddress::Witness))
        .or_else(|| find(&a.setup, PolyAddress::Setup))
        .unwrap_or_else(|| panic!("the toy has no column `{name}`"))
}

// ---------------------------------------------------------------------------
// The wire form
// ---------------------------------------------------------------------------

/// The toy round-trips byte for byte, and it is what carries `TreeCross` and
/// both range virtual kinds through the wire form.
#[test]
fn the_toy_round_trips_with_the_new_shapes() {
    let bytes = fixture_bytes(TOY, TOY_SHA256);
    let a = CircuitArtifact::from_bytes(&bytes).expect("decodes");
    assert_eq!(a.to_bytes(), bytes, "byte for byte");

    let crosses = a
        .layers
        .iter()
        .flat_map(|l| l.producing.iter())
        .filter(|e| matches!(e.gate, GateDef::TreeCross { .. }))
        .count();
    assert_eq!(
        crosses,
        VARS as usize * lookup_channel::COUNT as usize,
        "one TreeCross per channel per halving list"
    );
    let kinds: Vec<VirtualKind> = a.virtuals.iter().map(|(k, _)| *k).collect();
    assert_eq!(kinds, vec![VirtualKind::Range19, VirtualKind::Range16]);
    assert_eq!(MASK_BITS, 12, "the toy splits the packed mask into twelve");
}

/// `V[range19]` is wire tag 2 and `V[range16]` tag 3, appended after S13's
/// `RowIndex` and S14's `RamLive`; a `TreeCross` is gate tag 6, appended after
/// S13's six shapes. Each is checked through the one encoder, on a gate and an
/// address of its own.
#[test]
fn the_new_wire_tags_are_appended_and_round_trip() {
    let tag = |a: PolyAddress| {
        let gate = GateDef::Linear {
            terms: vec![(lit(1), a)],
            constant: lit(0),
        };
        let bytes = postcard::to_extend(&gate, Vec::new()).expect("encodes");
        // GateDef: tag, split, coefficients, operands; the address's three
        // words follow the two coefficient words of its single literal.
        bytes
    };
    for (kind, expected) in [(VirtualKind::Range19, 2u8), (VirtualKind::Range16, 3)] {
        let bytes = tag(PolyAddress::Virtual(kind));
        assert!(
            bytes.windows(3).any(|w| w == [3u8, expected, 0]),
            "{kind:?} is tag 3 with kind {expected}"
        );
    }
    let cross = GateDef::TreeCross {
        left: w(0),
        right: w(1),
    };
    let bytes = postcard::to_extend(&cross, Vec::new()).expect("encodes");
    assert_eq!(bytes[0], 6, "TreeCross is gate tag 6");
    let back: GateDef = postcard::from_bytes(&bytes).expect("decodes");
    assert_eq!(back, cross);
}
