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
    beta_power, check_copowers, check_discharge, range_table, table_denominator, ChannelSpec,
};
use constraints::memory::{frame_queries, frame_with_channels_artifact, Extras};
use constraints::{CircuitArtifact, Coeff, GateDef, LookupExpr, PolyAddress, VirtualKind};
use field::Fr;

/// `tools/kat-gen/src/lookup.rs`'s output.
const TOY: &str = "lookup_toy.bin";
const TOY_SHA256: &str = "975ee4d572a09399c30987eb2a8e8ad9d2b66a2445c8888d331d34343f9409d6";

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
    assert_eq!(check_discharge(&a), Ok(()));

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

    // The frame's own obligations come first, then the extras'.
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
    assert_eq!(check_discharge(&toy()), Ok(()));

    // Unconsumed: a lookup the circuit's leaves do not carry.
    let mut unconsumed = toy();
    let mut extra = unconsumed.lookups[0].clone();
    extra.name = "gap_hi_pc_again".to_string();
    extra.tuple = vec![column(w(1))];
    unconsumed.lookups.push(extra);
    assert_eq!(
        check_discharge(&unconsumed),
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
    let e = check_discharge(&doubled).expect_err("a doubly-consumed obligation");
    assert!(
        e.starts_with("lookup discharge: column `gap_hi_pc_den` is the denominator of 2 lookups"),
        "{e}"
    );
}

// ---------------------------------------------------------------------------
// The channel construction rules
// ---------------------------------------------------------------------------

/// A minimal `Extras` beside the frame: a timestamp obligation over one
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

fn extras(edit: fn(&mut Extras)) -> Extras {
    let boolean = |x: PolyAddress| GateDef::Quadratic {
        constant: lit(0),
        linear: vec![(lit(1), x)],
        products: vec![(Coeff::Literal(Fr::MINUS_ONE), x, x)],
    };
    let mut e = Extras {
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

fn build(vars: u32, edit: fn(&mut Extras)) -> CircuitArtifact {
    frame_with_channels_artifact(frame_queries(FAMILY), vars, extras(edit))
}

/// The control: the minimal extras build a circuit at the toy's height, with a
/// range channel and a table channel side by side.
#[test]
fn the_minimal_extras_build_a_circuit() {
    let a = build(VARS, |_| {});
    assert_eq!(a.validate(), Ok(()));
    assert_eq!(check_discharge(&a), Ok(()));
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

/// Every copower-scaled column carries a direct range check of its own. The
/// toy bounds `word_hi` directly, so a copower over it passes; `word` is
/// reached only through `word − 2^16·word_hi`, which is a scaled bound and
/// bounds nothing on its own, so a copower over it is refused.
///
/// Why the scaled half is not enough: a copower turns `x < p` into
/// `x·p' < 2^32` with `p·p' = 2^32`, and `p'` is a unit in `Fr`, so
/// `x = s·p'^{-1}` sweeps a coset of `2^32` elements almost none of which are
/// small integers. The range check on `s` sees nothing wrong.
#[test]
fn a_copower_scaled_column_needs_its_own_direct_range_check() {
    let a = toy();
    let word_hi = at(&a, "word_hi");
    let word = at(&a, "word");
    assert_eq!(check_copowers(&a, &[word_hi]), Ok(()));
    assert_eq!(check_copowers(&a, &[]), Ok(()));
    let e = check_copowers(&a, &[word]).expect_err("word has no direct bound");
    assert!(
        e.contains("is copower-scaled, but no range16 obligation bounds it directly"),
        "{e}"
    );
    // A column with no obligation at all is refused too.
    assert!(check_copowers(&a, &[at(&a, "and_a")]).is_err());
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
