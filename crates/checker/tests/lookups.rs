//! The lookup element, `docs/spec/memory.md` §7. `check_laws` holds every
//! lookup to the rules of `docs/spec/gkr.md` §4.2 with code of its own, and
//! agrees with `CircuitArtifact::validate` on every mutant below: 6 lawful — an
//! `M`, a `W` and an `S` selector and the `range16` channel among them — and 29
//! breaking one rule each, on both toys. `violated_lookups`, the native
//! evaluator, reports exactly the lookups a row breaks, reads each lookup's bound
//! from its own channel, and an evaluator reporting nothing, or everything, fails
//! the same cases.

mod common;

use checker::{
    check_channel_roots, check_laws, check_lookup_discharge, violated_lookups, ChannelSum,
    WitnessRow,
};
use common::*;
use constants::{challenge_slot, lookup_channel, memory::RAM_LIVE_BIT};
use constraints::{CircuitArtifact, Coeff, GateDef, LookupExpr, PolyAddress, VirtualKind};
use field::Fr;

const S0: PolyAddress = PolyAddress::Setup(0);
const LIVE: PolyAddress = PolyAddress::Virtual(VirtualKind::RamLive);

fn neg(v: u64) -> Coeff {
    Coeff::Literal(-Fr::from_u64(v))
}

fn expression(terms: &[(Coeff, PolyAddress)], constant: Coeff) -> GateDef {
    GateDef::Linear {
        terms: terms.to_vec(),
        constant,
    }
}

fn lookup(name: &str, selector: PolyAddress, expression: GateDef) -> LookupExpr {
    LookupExpr {
        name: name.to_string(),
        channel: lookup_channel::TIMESTAMP,
        selector,
        tuple: vec![expression],
    }
}

// ---------------------------------------------------------------------------
// The rules
// ---------------------------------------------------------------------------

struct Mutant {
    name: &'static str,
    lawful: bool,
    mutate: fn(&mut CircuitArtifact),
}

fn m(name: &'static str, lawful: bool, mutate: fn(&mut CircuitArtifact)) -> Mutant {
    Mutant {
        name,
        lawful,
        mutate,
    }
}

/// Push `range` — `4·m − row − 1` under selector `s` — edited by `edit`.
fn push(a: &mut CircuitArtifact, edit: fn(&mut LookupExpr)) {
    let mut l = lookup(
        "range",
        S0,
        expression(&[(lit(4), M0), (neg(1), V)], neg(1)),
    );
    edit(&mut l);
    a.lookups.push(l);
}

/// Push `range` named `name`, which some other part of the artifact already
/// carries.
fn push_named(a: &mut CircuitArtifact, name: String) {
    push(a, |_| {});
    a.lookups.last_mut().expect("pushed").name = name;
}

/// Push `range` reading `operand` alone, or under the selector `operand`.
fn push_reading(a: &mut CircuitArtifact, operand: PolyAddress, as_selector: bool) {
    push(a, |_| {});
    let l = a.lookups.last_mut().expect("pushed");
    match as_selector {
        true => l.selector = operand,
        false => l.tuple[0] = expression(&[(lit(1), operand)], lit(0)),
    }
}

fn mutants() -> Vec<Mutant> {
    vec![
        m("one lookup", true, |a| push(a, |_| {})),
        m("two lookups", true, |a| {
            push(a, |_| {});
            push(a, |l| {
                l.name = "range_2".to_string();
                l.selector = W1;
            });
        }),
        m(
            "an expression over M, W and S under a W selector",
            true,
            |a| {
                push(a, |l| {
                    l.selector = W1;
                    l.tuple[0] = expression(&[(lit(1), M0), (lit(1), W3), (lit(1), S0)], lit(0));
                })
            },
        ),
        m("an M selector", true, |a| push(a, |l| l.selector = M0)),
        m("the range16 channel", true, |a| {
            push(a, |l| l.channel = lookup_channel::RANGE16)
        }),
        m("an expression reading a listed V[ram_live]", true, |a| {
            a.virtuals
                .push((VirtualKind::RamLive, "ram_live".to_string()));
            push(a, |l| l.tuple[0] = expression(&[(lit(1), LIVE)], neg(1)));
        }),
        m("a channel past constants::lookup_channel", false, |a| {
            push(a, |l| l.channel = lookup_channel::NAMES.len() as u32)
        }),
        m("channel u32::MAX", false, |a| {
            push(a, |l| l.channel = u32::MAX)
        }),
        m("a tuple of no expression", false, |a| {
            push(a, |l| l.tuple.clear())
        }),
        m("a tuple of two expressions", false, |a| {
            push(a, |l| l.tuple.push(l.tuple[0].clone()))
        }),
        m("a Product expression", false, |a| {
            push(a, |l| {
                l.tuple[0] = GateDef::Product {
                    coeff: lit(1),
                    left: M0,
                    right: W0,
                }
            })
        }),
        m("a Quadratic expression of linear terms only", false, |a| {
            push(a, |l| {
                l.tuple[0] = GateDef::Quadratic {
                    constant: lit(0),
                    linear: vec![(lit(1), M0)],
                    products: vec![],
                }
            })
        }),
        m("a challenge coefficient on a term", false, |a| {
            push(a, |l| {
                let gamma = Coeff::Challenge(challenge_slot::TOY);
                l.tuple[0] = expression(&[(gamma, M0)], lit(0));
            })
        }),
        m("a challenge constant", false, |a| {
            push(a, |l| {
                let gamma = Coeff::Challenge(challenge_slot::TOY);
                l.tuple[0] = expression(&[(lit(1), M0)], gamma);
            })
        }),
        m("an expression reading L{1}[0]", false, |a| {
            push(a, |l| {
                l.tuple[0] = expression(&[(lit(1), inner(1, 0))], lit(0))
            })
        }),
        m("an expression reading scratch[0]", false, |a| {
            push(a, |l| {
                l.tuple[0] = expression(&[(lit(1), PolyAddress::Scratch(0))], lit(0))
            })
        }),
        m("an expression reading C{0}[0]", false, |a| {
            push(a, |l| {
                let c = PolyAddress::Cached {
                    layer: 0,
                    offset: 0,
                };
                l.tuple[0] = expression(&[(lit(1), c)], lit(0));
            })
        }),
        m("an expression reading W[4], past the layout", false, |a| {
            push(a, |l| {
                l.tuple[0] = expression(&[(lit(1), PolyAddress::Witness(4))], lit(0))
            })
        }),
        m("an expression reading V[ram_live], unlisted", false, |a| {
            push(a, |l| l.tuple[0] = expression(&[(lit(1), LIVE)], lit(0)))
        }),
        m("selector V[row]", false, |a| push(a, |l| l.selector = V)),
        m("selector W[4], past the layout", false, |a| {
            push(a, |l| l.selector = PolyAddress::Witness(4))
        }),
        m("an expression reading S past the layout", false, |a| {
            push_reading(a, PolyAddress::Setup(a.setup.len() as u32), false)
        }),
        m("selector S past the layout", false, |a| {
            push_reading(a, PolyAddress::Setup(a.setup.len() as u32), true)
        }),
        m("an expression reading M past the layout", false, |a| {
            push_reading(a, PolyAddress::Memory(a.memory.len() as u32), false)
        }),
        m("selector M past the layout", false, |a| {
            push_reading(a, PolyAddress::Memory(a.memory.len() as u32), true)
        }),
        m("selector L{1}[0]", false, |a| {
            push(a, |l| l.selector = inner(1, 0))
        }),
        m("a witness column's name", false, |a| {
            push(a, |l| l.name = "a".to_string())
        }),
        m("a memory column's name", false, |a| {
            push_named(a, a.memory[0].clone())
        }),
        m("a setup column's name", false, |a| {
            push_named(a, a.setup[0].clone())
        }),
        m("a listed virtual table's name", false, |a| {
            push_named(a, a.virtuals[0].1.clone())
        }),
        m("a relation's name", false, |a| {
            push_named(a, a.relations[0].name.clone())
        }),
        m("a scratch slot's name", false, |a| {
            push_named(a, a.scratch[0].name.clone())
        }),
        m("one name for two lookups", false, |a| {
            push(a, |_| {});
            push(a, |l| l.selector = W1);
        }),
        m("an uppercase name", false, |a| {
            push(a, |l| l.name = "Range".to_string())
        }),
        m("an empty name", false, |a| {
            push(a, |l| l.name = String::new())
        }),
    ]
}

/// Every mutant on both toys: `check_laws` and `validate` agree, on the verdict
/// the mutant is written with, and a refusal by `check_laws` names the lookup
/// rules.
#[test]
fn check_laws_agrees_with_validate_on_every_lookup_mutant() {
    let mut runs = 0;
    for (label, toy) in selectable_toys() {
        assert!(toy.lookups.is_empty(), "{label}");
        for mutant in mutants() {
            let mut a = toy.clone();
            (mutant.mutate)(&mut a);
            let (ours, theirs) = (check_laws(&a), a.validate());
            let name = mutant.name;
            assert_eq!(
                ours.is_ok(),
                theirs.is_ok(),
                "{label} `{name}`: check_laws {ours:?}, validate {theirs:?}"
            );
            assert_eq!(ours.is_ok(), mutant.lawful, "{label} `{name}`: {ours:?}");
            if let Err(e) = ours {
                assert!(
                    e.starts_with("Lookup rules: lookup "),
                    "{label} `{name}`: {e}"
                );
            }
            runs += 1;
        }
    }
    assert_eq!(runs, 2 * 35, "mutant runs");
}

// ---------------------------------------------------------------------------
// The native evaluator
// ---------------------------------------------------------------------------

/// The toy with `V[ram_live]` listed and three lookups on the timestamp
/// channel, `[0, 2^19)`:
///
/// ```text
/// m_small       selector s   m
/// row_after_a   selector b   row − a − 1
/// live          selector e   ram_live − 1
/// ```
fn with_lookups(mut a: CircuitArtifact) -> CircuitArtifact {
    a.virtuals
        .push((VirtualKind::RamLive, "ram_live".to_string()));
    a.lookups = vec![
        lookup("m_small", S0, expression(&[(lit(1), M0)], lit(0))),
        lookup(
            "row_after_a",
            W1,
            expression(&[(lit(1), V), (neg(1), W0)], neg(1)),
        ),
        lookup("live", W3, expression(&[(lit(1), LIVE)], neg(1))),
    ];
    assert_eq!(check_laws(&a), Ok(()));
    assert_eq!(a.validate(), Ok(()));
    a
}

/// Cases, each `(what, committed cells, row index, lookups violated)`; every
/// cell not given is 0. Why, case by case: a lookup whose selector is 0 holds
/// whatever its expression; any nonzero selector, 2 included, switches it on;
/// `2^19 − 1` is in range and `2^19` is not; `−1` is the canonical integer
/// `p − 1`, not a small negative number; `row − a − 1` is read at the row the
/// witness names, so the same cells break it at row 4 and keep it at row 5;
/// `ram_live − 1` is `−1` below row `2^14` and 0 from it.
#[allow(clippy::type_complexity)]
fn cases() -> Vec<(&'static str, Vec<(usize, Fr)>, usize, Vec<&'static str>)> {
    let (one, two, three, four) = (Fr::ONE, Fr::from_u64(2), Fr::from_u64(3), Fr::from_u64(4));
    let bound = Fr::from_u64(1 << 19);
    let live = 1usize << RAM_LIVE_BIT;
    vec![
        (
            "every selector 0, every expression out of range",
            vec![(M, bound), (A, Fr::from_u64(16))],
            4,
            vec![],
        ),
        (
            "m = 2^19 − 1 under s = 1",
            vec![(S, one), (M, bound - one)],
            4,
            vec![],
        ),
        (
            "m = 2^19 under s = 1",
            vec![(S, one), (M, bound)],
            4,
            vec!["m_small"],
        ),
        (
            "m = 2^19 under s = 2",
            vec![(S, two), (M, bound)],
            4,
            vec!["m_small"],
        ),
        (
            "m = −1 under s = 1",
            vec![(S, one), (M, -one)],
            4,
            vec!["m_small"],
        ),
        (
            "row 4, a = 3 under b = 1",
            vec![(B, one), (A, three)],
            4,
            vec![],
        ),
        (
            "row 4, a = 4 under b = 1",
            vec![(B, one), (A, four)],
            4,
            vec!["row_after_a"],
        ),
        (
            "row 5, a = 4 under b = 1",
            vec![(B, one), (A, four)],
            5,
            vec![],
        ),
        (
            "row 2^14 − 1 under e = 1",
            vec![(E, one)],
            live - 1,
            vec!["live"],
        ),
        ("row 2^14 under e = 1", vec![(E, one)], live, vec![]),
        (
            "all three at once",
            vec![(S, one), (M, bound), (B, one), (A, four), (E, one)],
            4,
            vec!["m_small", "row_after_a", "live"],
        ),
    ]
}

type Evaluator = fn(&CircuitArtifact, &WitnessRow) -> Vec<String>;

/// Every case, on both compilations.
fn run(evaluate: Evaluator) -> Result<(), String> {
    for (label, toy) in selectable_toys() {
        let a = with_lookups(toy);
        for (what, cells, row, want) in cases() {
            let mut committed = vec![Fr::ZERO; a.committed().len()];
            for (i, value) in cells {
                committed[i] = value;
            }
            let w = WitnessRow {
                committed,
                row,
                scratch: vec![Fr::ZERO; a.scratch.len()],
            };
            let got = evaluate(&a, &w);
            if got != want {
                return Err(format!("{label}, {what}: reports {got:?}, not {want:?}"));
            }
        }
    }
    Ok(())
}

/// The native evaluator reads a lookup's bound from its own channel: `m` under
/// `s = 1` on `range16` holds at `2^16 − 1` and is violated at `2^16`, a value
/// the timestamp channel's `[0, 2^19)` would admit. Fails if the evaluator
/// read every lookup against one channel's bound.
#[test]
fn a_range16_lookup_is_bound_below_2_16() {
    for (label, mut a) in selectable_toys() {
        let mut l = lookup("m_halfword", S0, expression(&[(lit(1), M0)], lit(0)));
        l.channel = lookup_channel::RANGE16;
        a.lookups.push(l);
        assert_eq!(check_laws(&a), Ok(()), "{label}");
        for (m, violated) in [((1 << 16) - 1, false), (1 << 16, true)] {
            let mut committed = vec![Fr::ZERO; a.committed().len()];
            (committed[S], committed[M]) = (Fr::ONE, Fr::from_u64(m));
            let w = WitnessRow {
                committed,
                row: 0,
                scratch: vec![Fr::ZERO; a.scratch.len()],
            };
            let names = violated_lookups(&a, &w);
            assert_eq!(
                names.len(),
                violated as usize,
                "{label}, m = {m}: {names:?}"
            );
        }
    }
}

#[test]
fn violated_lookups_reports_exactly_the_lookups_a_row_breaks() {
    assert_eq!(run(violated_lookups), Ok(()));
}

#[test]
fn an_evaluator_reporting_nothing_fails_the_same_cases() {
    assert!(run(|_, _| Vec::new()).is_err());
}

#[test]
fn an_evaluator_reporting_everything_fails_the_same_cases() {
    let everything: Evaluator = |a, _| a.lookups.iter().map(|l| l.name.clone()).collect();
    assert!(run(everything).is_err());
}

// ---------------------------------------------------------------------------
// The selector's booleanity, and the LogUp checkers' negative controls
// ---------------------------------------------------------------------------

/// S15's selector rule, on the checker's side: `check_laws` refuses a lookup
/// whose selector gate list 0 does not hold to `x − x·x = 0`, and `validate`
/// agrees. Kills a `holds_booleanity` that returns true for anything — without
/// which the rule would be enforced once, not twice.
///
/// Why the rule is needed: LogUp sums `s/(E + g)` over the rows, so a row at
/// `s = −1` with an out-of-range tuple cancels a row at `s = 1` with the same
/// tuple, and a gap of −1 that `violated_lookups` reports would pass.
#[test]
fn a_selector_without_a_booleanity_gate_is_refused_by_both() {
    for (label, toy) in selectable_toys() {
        // W0 is `a`, which no booleanity gate holds; W1 is `b`, which one does.
        let mut a = toy.clone();
        a.lookups
            .push(lookup("range", W0, expression(&[(lit(1), M0)], lit(0))));
        let ours = check_laws(&a).expect_err("a selector with no booleanity gate");
        assert!(
            ours.ends_with("gate list 0 does not hold selector W[0] to booleanity"),
            "{label}: {ours}"
        );
        assert!(a.validate().is_err(), "{label}: validate agrees");

        let mut lawful = toy;
        lawful
            .lookups
            .push(lookup("range", W1, expression(&[(lit(1), M0)], lit(0))));
        assert_eq!(check_laws(&lawful), Ok(()), "{label}");
        assert_eq!(lawful.validate(), Ok(()), "{label}");
    }
}

/// `checker::check_lookup_discharge`'s negative controls, the twins of
/// `constraints/tests/lookup.rs`' — an obligation nothing discharges, and one
/// two columns discharge. Kills a check that returns `Ok` whatever it is
/// handed, which is what master rule 8 asks of every checker.
#[test]
fn the_discharge_cross_check_refuses_an_unconsumed_and_a_doubled_obligation() {
    for (label, toy) in selectable_toys() {
        // The toy has no channel, so its gate list 0 discharges nothing: one
        // lookup is already one too many.
        let mut unconsumed = toy.clone();
        push(&mut unconsumed, |_| {});
        assert_eq!(check_laws(&unconsumed), Ok(()), "{label}");
        let e = check_lookup_discharge(&unconsumed, &[]).expect_err("nothing discharges it");
        assert!(
            e.contains("lookup `range` is the denominator of 0 gate-list-0 columns"),
            "{label}: {e}"
        );

        let _ = toy;
    }

    // A column that is two lookups' denominator needs a circuit whose gate list
    // 0 has denominators at all, which the S13 toy does not: S15's combined toy
    // with one of its lookups duplicated.
    let mut doubled = lookup_toy();
    assert_eq!(check_lookup_discharge(&doubled, &[]), Ok(()));
    let mut twin = doubled.lookups[0].clone();
    twin.name = format!("{}_twin", twin.name);
    let name = doubled.lookups[0].name.clone();
    doubled.lookups.push(twin);
    let e = check_lookup_discharge(&doubled, &[]).expect_err("two lookups, one column");
    assert!(
        e.contains(&format!(
            "column `{name}_den` is the denominator of 2 lookups"
        )),
        "{e}"
    );
}

/// S15's combined toy, the one committed circuit whose gate list 0 carries
/// lookup denominators.
fn lookup_toy() -> CircuitArtifact {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../constraints/tests/vectors/lookup_toy.bin"
    );
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    CircuitArtifact::from_bytes(&bytes).expect("the S15 toy decodes")
}

/// `checker::check_channel_roots`' negative control: a root pair that is not the
/// native recomputation is refused, on each half of the pair separately. Kills a
/// comparison that looks at one half, or at neither.
#[test]
fn the_channel_root_comparison_refuses_each_half_alone() {
    let sums = vec![ChannelSum {
        channel: lookup_channel::TIMESTAMP,
        num: Fr::from_u64(7),
        den: Fr::from_u64(11),
        unmatched: Vec::new(),
    }];
    assert_eq!(
        check_channel_roots(&[(Fr::from_u64(7), Fr::from_u64(11))], &sums),
        Ok(())
    );
    let moved = |num: u64, den: u64| {
        check_channel_roots(&[(Fr::from_u64(num), Fr::from_u64(den))], &sums)
            .expect_err("a root that is not the recomputation")
    };
    assert!(moved(8, 11).contains("num root is not its fractional sum's numerator"));
    assert!(moved(7, 12).contains("den root is not the product of its leaf denominators"));
    assert!(check_channel_roots(&[], &sums).is_err(), "a missing pair");
}
