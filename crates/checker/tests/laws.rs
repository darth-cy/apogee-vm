//! Acceptance 5: every law validator passes both committed toys and rejects a
//! hand-built artifact breaking its law, naming that law — and the mutants that
//! break one law are shown to pass the others, so each failure is attributable.
//!
//! The same mutants drive a differential test against `constraints`' own
//! construction-time check, `CircuitArtifact::validate`, which shares no code
//! with `checker`: the two enforcement points must agree on every mutant whose
//! only defects are law violations. (`validate` also refuses things outside the
//! laws — the degree ceiling, names, an inner column no gate reads, a cached
//! entry no gate names, the halving rules — so a mutant that breaks one of those
//! as well is marked `only_laws: false` and left out of that comparison.)

mod common;

use checker::{check_law1, check_law2, check_law3, check_law4, check_laws};
use common::*;
use constraints::{CircuitArtifact, GateDef, PolyAddress};

type Law = fn(&CircuitArtifact) -> Result<(), String>;

const LAWS: [Law; 4] = [check_law1, check_law2, check_law3, check_law4];

struct Mutant {
    name: &'static str,
    /// The lowest law the mutant breaks, which `check_laws` reports; 0 if none.
    law: usize,
    /// Every other law it breaks.
    also: &'static [usize],
    /// Whether its only defects are law violations (see the module docs).
    only_laws: bool,
    mutate: fn(&mut CircuitArtifact),
}

fn m(
    name: &'static str,
    law: usize,
    also: &'static [usize],
    mutate: fn(&mut CircuitArtifact),
) -> Mutant {
    Mutant {
        name,
        law,
        also,
        only_laws: true,
        mutate,
    }
}

/// Swap two inner addresses everywhere a gate reads them.
fn swap_reads(gate: &mut GateDef, x: PolyAddress, y: PolyAddress) {
    let parked = inner(99, 99);
    set_operand(gate, x, parked);
    set_operand(gate, y, x);
    set_operand(gate, parked, y);
}

/// Mutants valid for both compilations.
fn mutants() -> Vec<Mutant> {
    vec![
        // Lawful edits: every law holds, and `validate` must agree.
        m("unmutated", 0, &[], |_| {}),
        m(
            "a literal changed in a relation and its gate alike",
            0,
            &[],
            |a| {
                let r = relation(a, "define_fingerprint3");
                *linear(&mut a.relations[r].gate).1 = lit(4);
                *linear(&mut a.layers[1].producing[1].gate).1 = lit(4);
            },
        ),
        m("the output map reordered", 0, &[], |a| a.outputs.reverse()),
        m("a committed column renamed", 0, &[], |a| {
            a.witness[0] = "alpha".to_string()
        }),
        // Law 1: a gate reading two layers down, or outside what its layer holds.
        m(
            "list 1 reads W[0], two layers down, gate and relation alike",
            1,
            &[],
            |a| {
                let r = relation(a, "define_fingerprint3");
                linear(&mut a.relations[r].gate).0.push((lit(1), W0));
                linear(&mut a.layers[1].producing[1].gate)
                    .0
                    .push((lit(1), W0));
            },
        ),
        m(
            "list 1 reads V[row], a layer-0 table, gate and relation alike",
            1,
            &[],
            |a| {
                let r = relation(a, "define_fingerprint3");
                linear(&mut a.relations[r].gate).0.push((lit(1), V));
                linear(&mut a.layers[1].producing[1].gate)
                    .0
                    .push((lit(1), V));
            },
        ),
        Mutant {
            // L{2}[0] is then read by no gate, and a halving gate stops
            // reading its own column (Law 2).
            only_laws: false,
            ..m(
                "list 2 reads L{1}[0], two layers down, gate and relation alike",
                1,
                &[2],
                |a| {
                    a.layers[2].producing[0].gate = GateDef::TreeProduct { input: inner(1, 0) };
                    let (r, ab) = (relation(a, "define_abm_product"), slot(a, "ab") as u32);
                    a.relations[r].gate = GateDef::TreeProduct {
                        input: PolyAddress::Scratch(ab),
                    };
                },
            )
        },
        m("list 1 reads L{1}[3], past layer 1's width", 1, &[4], |a| {
            linear(&mut a.layers[1].producing[1].gate)
                .0
                .push((lit(1), inner(1, 3)));
        }),
        m(
            "an enforcing gate reads scratch[0]",
            1,
            &[4],
            |a| match &mut a.layers[0].enforcing[0].gate {
                GateDef::AffineProduct { right, .. } => {
                    right.push((lit(1), PolyAddress::Scratch(0)))
                }
                other => panic!("gated_equality is not an AffineProduct: {other:?}"),
            },
        ),
        // Law 2: a declared width or variable count the gates do not imply.
        m(
            "list 0 declares width 4, its gates write 3 (keccak_special5)",
            2,
            &[],
            |a| a.layers[0].width = 4,
        ),
        m("list 0 declares width 2, its gates write 3", 2, &[], |a| {
            a.layers[0].width = 2
        }),
        m(
            "row-wise list 1 declares 3 variables over a 4-variable layer",
            2,
            &[],
            |a| a.layers[1].num_vars = 3,
        ),
        m(
            "halving list 2 declares 4 variables over a 4-variable layer",
            2,
            &[],
            |a| a.layers[2].num_vars = 4,
        ),
        Mutant {
            // A row-wise list holding TreeProducts breaks a halving rule too.
            only_laws: false,
            ..m("list 2 marked row-wise", 2, &[], |a| {
                a.layers[2].halving = false
            })
        },
        m(
            "halving list 2 reads L{2}[1] then L{2}[0], gates and relations alike",
            2,
            &[],
            |a| {
                a.layers[2].producing[0].gate = GateDef::TreeProduct { input: inner(2, 1) };
                a.layers[2].producing[1].gate = GateDef::TreeProduct { input: inner(2, 0) };
                let (abm, fp3) = (slot(a, "abm") as u32, slot(a, "fingerprint3") as u32);
                let r = relation(a, "define_abm_product");
                a.relations[r].gate = GateDef::TreeProduct {
                    input: PolyAddress::Scratch(fp3),
                };
                let r = relation(a, "define_fingerprint3_product");
                a.relations[r].gate = GateDef::TreeProduct {
                    input: PolyAddress::Scratch(abm),
                };
            },
        ),
        m(
            "list 0 writes L{1}[1] then L{1}[0], renamed consistently everywhere",
            2,
            &[],
            |a| {
                a.layers[0].producing[0].output = inner(1, 1);
                a.layers[0].producing[1].output = inner(1, 0);
                let (ab, fp) = (slot(a, "ab"), slot(a, "fingerprint"));
                a.scratch[ab].address = inner(1, 1);
                a.scratch[fp].address = inner(1, 0);
                for e in &mut a.layers[1].producing {
                    swap_reads(&mut e.gate, inner(1, 0), inner(1, 1));
                }
            },
        ),
        // Law 3: a top layer and an output map that are not one set.
        m(
            "the output map drops L{3}[0], which the top layer holds",
            3,
            &[],
            |a| a.outputs.retain(|o| *o != inner(3, 0)),
        ),
        m(
            "the output map adds L{2}[0], which is not on the top layer",
            3,
            &[],
            |a| a.outputs.push(inner(2, 0)),
        ),
        m("the output map names L{3}[1] twice", 3, &[], |a| {
            a.outputs[1] = a.outputs[0]
        }),
        // Law 4, cardinality.
        m("a relation dropped from the flat list", 4, &[], |a| {
            let r = relation(a, "define_fingerprint3_product");
            a.relations.remove(r);
        }),
        m("a relation added to the flat list", 4, &[], |a| {
            let mut copy = a.relations[relation(a, "gated_equality")].clone();
            copy.name = "gated_equality_copy".to_string();
            a.relations.push(copy);
        }),
        m("two producing gates name the same relation", 4, &[], |a| {
            a.layers[1].producing[1].relation = a.layers[1].producing[0].relation
        }),
        m("the enforcing gate removed", 4, &[], |a| {
            a.layers[0].enforcing.clear()
        }),
        m(
            "an enforcing gate and a producing gate swap relations",
            4,
            &[],
            |a| {
                let list = &mut a.layers[0];
                std::mem::swap(
                    &mut list.enforcing[0].relation,
                    &mut list.producing[2].relation,
                );
            },
        ),
        // Law 4, outputs through the bijection.
        m("two relations swap their scratch outputs", 4, &[], |a| {
            let (x, y) = (relation(a, "define_ab"), relation(a, "define_fingerprint"));
            let out = a.relations[x].output;
            a.relations[x].output = a.relations[y].output;
            a.relations[y].output = out;
        }),
        m("the scratch bijection swaps two columns", 4, &[], |a| {
            let (x, y) = (slot(a, "ab"), slot(a, "fingerprint"));
            let address = a.scratch[x].address;
            a.scratch[x].address = a.scratch[y].address;
            a.scratch[y].address = address;
        }),
        // Law 4, semantics.
        m("a literal changed in one relation only", 4, &[], |a| {
            let r = relation(a, "define_fingerprint3");
            *linear(&mut a.relations[r].gate).1 = lit(4);
        }),
        m("a literal changed in one gate only", 4, &[], |a| {
            *linear(&mut a.layers[1].producing[1].gate).1 = lit(4);
        }),
        m(
            "a challenge turned literal in one relation only",
            4,
            &[],
            |a| {
                let r = relation(a, "define_fingerprint");
                assert_eq!(set_coefficient(&mut a.relations[r].gate, W0, lit(1)), 1);
            },
        ),
        m("an operand changed in one relation only", 4, &[], |a| {
            let r = relation(a, "define_ab");
            assert_eq!(set_operand(&mut a.relations[r].gate, W1, W2), 1);
        }),
        m(
            "a tree-product relation reads the wrong slot",
            4,
            &[],
            |a| {
                let (r, fp3) = (relation(a, "define_abm_product"), slot(a, "fingerprint3"));
                a.relations[r].gate = GateDef::TreeProduct {
                    input: PolyAddress::Scratch(fp3 as u32),
                };
            },
        ),
    ]
}

/// Mutants of the cached compilation's cached entry.
fn cached_mutants() -> Vec<Mutant> {
    vec![
        m(
            "a cached entry addressed C{0}[1] at position 0",
            1,
            &[],
            |a| {
                a.layers[0].cached[0].address = PolyAddress::Cached {
                    layer: 0,
                    offset: 1,
                };
            },
        ),
        m(
            "a cached entry's coefficient changed, its relation not",
            4,
            &[],
            |a| {
                assert_eq!(
                    set_coefficient(&mut a.layers[0].cached[0].gate, V, lit(2)),
                    1
                );
            },
        ),
    ]
}

/// Every mutant applied to every compilation it fits: (compilation, mutant,
/// mutated artifact).
fn mutated() -> Vec<(&'static str, Mutant, CircuitArtifact)> {
    let mut out = Vec::new();
    for (label, toy) in toys() {
        let mut all = mutants();
        if !toy.layers[0].cached.is_empty() {
            all.extend(cached_mutants());
        }
        for mutant in all {
            let mut a = toy.clone();
            (mutant.mutate)(&mut a);
            out.push((label, mutant, a));
        }
    }
    out
}

#[test]
fn every_law_passes_both_fixtures() {
    for (label, a) in toys() {
        for law in LAWS {
            assert_eq!(law(&a), Ok(()), "{label}");
        }
        assert_eq!(check_laws(&a), Ok(()), "{label}");
    }
}

/// Each mutant fails exactly the laws it breaks, each failure names its law,
/// and `check_laws` reports the lowest.
#[test]
fn every_mutant_fails_exactly_the_laws_it_breaks() {
    let all = mutated();
    for (label, mutant, a) in &all {
        for (i, law) in LAWS.iter().enumerate() {
            let number = i + 1;
            let broken = number == mutant.law || mutant.also.contains(&number);
            match law(a) {
                Ok(()) => assert!(!broken, "{label} `{}`: Law {number} passed", mutant.name),
                Err(e) => {
                    assert!(
                        broken,
                        "{label} `{}`: Law {number} failed: {e}",
                        mutant.name
                    );
                    let name = format!("Law {number} ");
                    assert!(e.starts_with(&name), "{label} `{}`: {e}", mutant.name);
                }
            }
        }
        match check_laws(a) {
            Ok(()) => assert_eq!(mutant.law, 0, "{label} `{}` passed", mutant.name),
            Err(e) => assert!(
                e.starts_with(&format!("Law {} ", mutant.law)),
                "{label} `{}`: {e}",
                mutant.name
            ),
        }
    }
    assert!(all.len() >= 2 * 30, "{} mutant runs", all.len());
}

/// `checker` and `constraints::validate` agree on every mutant whose only
/// defects are law violations. Disagreements are collected and reported
/// together rather than stopping at the first.
#[test]
fn check_laws_agrees_with_validate() {
    let mut compared = 0;
    let mut disagreements: Vec<String> = Vec::new();
    for (label, mutant, a) in &mutated() {
        if !mutant.only_laws {
            continue;
        }
        compared += 1;
        let (ours, theirs) = (check_laws(a), a.validate());
        if ours.is_ok() != theirs.is_ok() {
            disagreements.push(format!(
                "{label} `{}`: check_laws {ours:?}, validate {theirs:?}",
                mutant.name
            ));
        }
    }
    assert!(compared > 2 * 20, "only {compared} mutants compared");
    assert!(disagreements.is_empty(), "{}", disagreements.join("\n"));
}
