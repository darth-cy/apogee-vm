//! Acceptance 9: each committed toy artifact against an independent
//! description of the toy.
//!
//! `toy_constants` and `reference` are written from the toy's prose description
//! (the header of `tools/kat-gen/src/gkr.rs`, restated in `tests/common/mod.rs`)
//! and `docs/spec/gkr.md` — not from the code that builds the artifact, and not
//! by reading the artifact back. `reference` is plain field arithmetic: no gate,
//! no kernel, no layer.
//!
//! The sweep perturbs one artifact field at a time. Changing one encoding only
//! is caught by a law; the same change applied to both encodings passes the laws
//! (asserted) and is caught by the constants or the semantic comparison.
//!
//! Documentation-only, so NOT covered by `cross_check`: relation names other
//! than the enforcing relation's, cached entry names, and the names of scratch
//! slots that are not outputs (`documentation_only_fields_are_not_covered`
//! shows renaming them passes). Also outside it: `format_version`,
//! `coefficient_encoding`, `lookups`, and the padding contract, which is
//! `check_padding`'s.

mod common;

use checker::{check_laws, cross_check, ReferenceRun, VerifierConstants};
use common::*;
use constants::challenge_slot;
use constraints::{CachedEntry, CircuitArtifact, Coeff, GateDef, PolyAddress};
use field::Fr;
use gkr::ExternalChallenges;

/// What a verifier expects of the toy: 16 rows; list 0 row-wise, width 3, one
/// enforcing gate and `cached` cached entries; list 1 row-wise, width 2; list 2
/// halving both columns.
fn toy_constants(cached: usize) -> VerifierConstants {
    VerifierConstants {
        trace_vars: 4,
        memory: vec!["m"],
        witness: vec!["a", "b", "c", "e"],
        setup: vec!["s"],
        virtuals: vec!["row"],
        halving: vec![false, false, true],
        num_vars: vec![4, 4, 3],
        widths: vec![3, 2, 2],
        enforcing: vec![1, 0, 0],
        cached: vec![cached, 0, 0],
        outputs: vec!["fingerprint3_product", "abm_product"],
        challenge_slots: vec![challenge_slot::TOY],
    }
}

/// The toy by hand. `base` is `m, a, b, c, e, s`, 16 rows each.
fn reference(base: &[Vec<Fr>], challenges: &ExternalChallenges) -> ReferenceRun {
    let (m, a, b, c, e, s) = (&base[M], &base[A], &base[B], &base[C], &base[E], &base[S]);
    let gamma = challenges
        .get(challenge_slot::TOY)
        .expect("the toy's challenge");
    let rows = 16;
    let abm: Vec<Fr> = (0..rows)
        .map(|y| a[y] * b[y] * (m[y] * s[y] + Fr::ONE - s[y]))
        .collect();
    let fingerprint3: Vec<Fr> = (0..rows)
        .map(|y| (gamma * a[y] + Fr::from_u64(y as u64)) * c[y] + Fr::from_u64(3))
        .collect();
    // One halving: the child bit is the highest variable, so row i pairs with
    // row i + 8.
    let product = |t: &[Fr]| (0..rows / 2).map(|i| t[i] * t[i + rows / 2]).collect();
    let gated_equality = (0..rows).map(|y| (e[y] - a[y]) * s[y]).collect();
    ReferenceRun {
        outputs: vec![product(&fingerprint3), product(&abm)],
        enforcing: vec![("gated_equality".to_string(), gated_equality)],
    }
}

fn reference_one_row_off(base: &[Vec<Fr>], challenges: &ExternalChallenges) -> ReferenceRun {
    let mut run = reference(base, challenges);
    run.outputs[1][5] += Fr::ONE;
    run
}

fn reference_without_the_gate(base: &[Vec<Fr>], challenges: &ExternalChallenges) -> ReferenceRun {
    let mut run = reference(base, challenges);
    run.enforcing[0].1 = vec![Fr::ZERO; 16];
    run
}

fn toys_with_constants() -> [(&'static str, CircuitArtifact, VerifierConstants); 2] {
    [
        ("cached", load(CACHED), toy_constants(1)),
        ("cache-free", load(CACHE_FREE), toy_constants(0)),
    ]
}

#[test]
fn both_fixtures_agree_with_the_independent_description() {
    for (label, a, constants) in toys_with_constants() {
        assert_eq!(cross_check(&a, &constants, reference), Ok(()), "{label}");
    }
}

#[test]
fn a_wrong_description_is_rejected() {
    for (label, a, constants) in toys_with_constants() {
        let e = cross_check(&a, &constants, reference_one_row_off).unwrap_err();
        assert!(e.contains("output 1 differs"), "{label}: {e}");
        let e = cross_check(&a, &constants, reference_without_the_gate).unwrap_err();
        assert!(e.contains("enforcing relation 0 differs"), "{label}: {e}");
    }
}

struct Perturbation {
    name: &'static str,
    /// A substring of the error.
    caught_by: &'static str,
    /// Whether the perturbed artifact still passes Laws 1–4.
    laws_hold: bool,
    mutate: fn(&mut CircuitArtifact),
}

fn p(
    name: &'static str,
    caught_by: &'static str,
    laws_hold: bool,
    mutate: fn(&mut CircuitArtifact),
) -> Perturbation {
    Perturbation {
        name,
        caught_by,
        laws_hold,
        mutate,
    }
}

const REFERENCE: &str = "differs from the reference";

fn perturbations() -> Vec<Perturbation> {
    vec![
        p("a literal coefficient, in one gate", "Law 4", false, |a| {
            *linear(&mut a.layers[1].producing[1].gate).1 = lit(4);
        }),
        p(
            "a literal coefficient, in a gate and its relation",
            REFERENCE,
            true,
            |a| {
                *linear(&mut a.layers[1].producing[1].gate).1 = lit(4);
                let r = relation(a, "define_fingerprint3");
                *linear(&mut a.relations[r].gate).1 = lit(4);
            },
        ),
        p(
            "a challenge slot to a literal, in one relation",
            "Law 4",
            false,
            |a| {
                let r = relation(a, "define_fingerprint");
                assert_eq!(set_coefficient(&mut a.relations[r].gate, W0, lit(1)), 1);
            },
        ),
        p(
            "a challenge slot to a literal, everywhere it is read",
            "cross_check: challenge_slots",
            true,
            |a| {
                let r = relation(a, "define_fingerprint");
                assert_eq!(set_coefficient(&mut a.relations[r].gate, W0, lit(1)), 1);
                let list = &mut a.layers[0];
                let gates = list.cached.iter_mut().map(|e| &mut e.gate);
                let gates = gates.chain(list.producing.iter_mut().map(|e| &mut e.gate));
                let changed: usize = gates.map(|g| set_coefficient(g, W0, lit(1))).sum();
                assert_eq!(changed, 1);
            },
        ),
        p(
            "the challenge slot renumbered, everywhere it is read",
            "cross_check: challenge_slots",
            true,
            |a| {
                let r = relation(a, "define_fingerprint");
                set_coefficient(&mut a.relations[r].gate, W0, Coeff::Challenge(1));
                for e in &mut a.layers[0].cached {
                    set_coefficient(&mut e.gate, W0, Coeff::Challenge(1));
                }
                for e in &mut a.layers[0].producing {
                    set_coefficient(&mut e.gate, W0, Coeff::Challenge(1));
                }
            },
        ),
        p("an operand address, in one gate", "Law 4", false, |a| {
            assert_eq!(set_operand(&mut a.layers[0].producing[0].gate, W0, W2), 1);
        }),
        p(
            "an operand address, in a gate and its relation",
            REFERENCE,
            true,
            |a| {
                assert_eq!(set_operand(&mut a.layers[0].producing[0].gate, W0, W2), 1);
                let r = relation(a, "define_ab");
                assert_eq!(set_operand(&mut a.relations[r].gate, W0, W2), 1);
            },
        ),
        p(
            "an enforcing operand, in its gate and relation",
            "enforcing relation 0 differs",
            true,
            |a| {
                assert_eq!(set_operand(&mut a.layers[0].enforcing[0].gate, W0, W1), 1);
                let r = relation(a, "gated_equality");
                assert_eq!(set_operand(&mut a.relations[r].gate, W0, W1), 1);
            },
        ),
        p("a width", "Law 2", false, |a| a.layers[1].width = 3),
        p("a num_vars", "Law 2", false, |a| a.layers[2].num_vars = 4),
        p("trace_vars", "Law 2", false, |a| a.trace_vars = 5),
        p(
            "trace_vars and every num_vars after it",
            "cross_check: trace_vars",
            true,
            |a| {
                a.trace_vars = 5;
                for list in &mut a.layers {
                    list.num_vars += 1;
                }
            },
        ),
        p("the output order", "cross_check: outputs", true, |a| {
            a.outputs.reverse()
        }),
        p(
            "an output's scratch name",
            "cross_check: outputs",
            true,
            |a| {
                let i = slot(a, "abm_product");
                a.scratch[i].name = "abm_tree".to_string();
            },
        ),
        p(
            "a committed column name",
            "cross_check: witness",
            true,
            |a| a.witness[0] = "alpha".to_string(),
        ),
        p("a memory column name", "cross_check: memory", true, |a| {
            a.memory[0] = "mem".to_string()
        }),
        p("a setup column name", "cross_check: setup", true, |a| {
            a.setup[0] = "selector".to_string()
        }),
        p(
            "a cached entry added, `b` read through it",
            "cross_check: cached",
            true,
            |a| {
                let list = &mut a.layers[0];
                let alias = PolyAddress::Cached {
                    layer: 0,
                    offset: list.cached.len() as u32,
                };
                list.cached.push(CachedEntry {
                    name: "b_alias".to_string(),
                    address: alias,
                    gate: GateDef::Linear {
                        terms: vec![(lit(1), W1)],
                        constant: lit(0),
                    },
                });
                assert_eq!(set_operand(&mut list.producing[0].gate, W1, alias), 1);
            },
        ),
        p("a virtual table name", "cross_check: virtuals", true, |a| {
            a.virtuals[0].1 = "index".to_string()
        }),
        p("the halving flag", "Law 2", false, |a| {
            a.layers[2].halving = false
        }),
        p("an enforcing gate removed", "Law 4", false, |a| {
            a.layers[0].enforcing.clear()
        }),
        p(
            "an enforcing gate removed with its relation",
            "cross_check: enforcing",
            true,
            |a| {
                let r = relation(a, "gated_equality");
                a.relations.remove(r);
                a.layers[0].enforcing.clear();
                for list in &mut a.layers {
                    for e in &mut list.producing {
                        if e.relation as usize > r {
                            e.relation -= 1;
                        }
                    }
                }
            },
        ),
        // In the cache-free compilation the same term sits inline in the gate.
        p("a cached entry's coefficient", "Law 4", false, |a| {
            let list = &mut a.layers[0];
            let gates = list.cached.iter_mut().map(|e| &mut e.gate);
            let gates = gates.chain(list.producing.iter_mut().map(|e| &mut e.gate));
            let changed: usize = gates.map(|g| set_coefficient(g, V, lit(2))).sum();
            assert_eq!(changed, 1);
        }),
        p(
            "a cached entry's coefficient and its relation's",
            REFERENCE,
            true,
            |a| {
                let list = &mut a.layers[0];
                let gates = list.cached.iter_mut().map(|e| &mut e.gate);
                let gates = gates.chain(list.producing.iter_mut().map(|e| &mut e.gate));
                let changed: usize = gates.map(|g| set_coefficient(g, V, lit(2))).sum();
                assert_eq!(changed, 1);
                let r = relation(a, "define_fingerprint");
                assert_eq!(set_coefficient(&mut a.relations[r].gate, V, lit(2)), 1);
            },
        ),
    ]
}

#[test]
fn every_single_field_perturbation_is_caught() {
    for (label, toy, constants) in toys_with_constants() {
        for perturbation in perturbations() {
            let name = perturbation.name;
            let mut a = toy.clone();
            (perturbation.mutate)(&mut a);
            assert_eq!(
                check_laws(&a).is_ok(),
                perturbation.laws_hold,
                "{label} `{name}`"
            );
            let e = cross_check(&a, &constants, reference)
                .expect_err(&format!("{label} `{name}` passed the cross-check"));
            assert!(e.contains(perturbation.caught_by), "{label} `{name}`: {e}");
        }
    }
}

#[test]
fn documentation_only_fields_are_not_covered() {
    for (label, mut a, constants) in toys_with_constants() {
        let r = relation(&a, "define_ab");
        a.relations[r].name = "define_a_times_b".to_string();
        let i = slot(&a, "ab");
        a.scratch[i].name = "a_times_b".to_string();
        for e in &mut a.layers[0].cached {
            e.name = "gamma_a_plus_row".to_string();
        }
        assert_eq!(cross_check(&a, &constants, reference), Ok(()), "{label}");
    }
}
