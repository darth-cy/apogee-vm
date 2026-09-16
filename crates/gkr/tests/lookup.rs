//! S15's engine additions, each cheap enough for ordinary CI: the halving
//! cross gate end to end over a hand-written fraction circuit, the two range
//! tables' closed forms against the tables themselves (acceptance 9), the
//! derived LogUp challenge slots, and the root check.

use constants::{challenge_slot, lookup_channel};
use constraints::{
    CircuitArtifact, Coeff, GateDef, LayerSpec, Padding, PolyAddress, ProducingEntry, Relation,
    ScratchSlot, VirtualKind, COEFFICIENT_ENCODING_CANONICAL_LE, FORMAT_VERSION,
};
use field::Fr;
use gkr::{
    channel_holds, forward, insert_lookup_challenges, prove, self_check, verify, virtual_at_point,
    virtual_at_row, BaseLayer, ExternalChallenges, GkrError, OutputClaims,
};
use poly::{MultilinearPoly, PolyBacking};
use sumcheck::{absorb_witness_digest, witness_digest};
use test_support::Rng;
use transcript::Transcript;

fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

fn inner(layer: u32, offset: u32) -> PolyAddress {
    PolyAddress::Inner { layer, offset }
}

fn fr(rng: &mut Rng) -> Fr {
    let mut b = rng.next_le32();
    b[31] &= 0x0f;
    Fr::from_bytes(&b).expect("below 2^252")
}

// ---------------------------------------------------------------------------
// The fraction tree, end to end
// ---------------------------------------------------------------------------

/// A hand-written fraction circuit over `2^vars` rows: `W[0] p` and `W[1] q`
/// copied into layer 1, then `vars` halving lists, each writing
/// `TreeCross { p, q }` and `TreeProduct { q }`. Its outputs are the pair
/// `(Σ_y p_y/q_y · Π_y q_y, Π_y q_y)` — the fraction tree of
/// `docs/spec/lookup.md` §6, with nothing else in the circuit.
///
/// Written out here rather than taken from `constraints`, which builds no
/// circuit this small: every lookup channel a real one carries brings its own
/// table, and the timestamp channel's needs 2^19 rows.
fn fraction_circuit(vars: u32) -> CircuitArtifact {
    let copy = |x: PolyAddress| GateDef::Linear {
        terms: vec![(lit(1), x)],
        constant: lit(0),
    };
    let mut layers = vec![LayerSpec {
        halving: false,
        num_vars: vars,
        width: 2,
        cached: vec![],
        producing: vec![
            ProducingEntry {
                relation: 0,
                output: inner(1, 0),
                gate: copy(PolyAddress::Witness(0)),
            },
            ProducingEntry {
                relation: 1,
                output: inner(1, 1),
                gate: copy(PolyAddress::Witness(1)),
            },
        ],
        enforcing: vec![],
    }];
    let mut relations = vec![
        Relation {
            name: "define_num_1".into(),
            output: Some(0),
            gate: copy(PolyAddress::Witness(0)),
        },
        Relation {
            name: "define_den_1".into(),
            output: Some(1),
            gate: copy(PolyAddress::Witness(1)),
        },
    ];
    let mut scratch = vec![
        ScratchSlot {
            name: "num_1".into(),
            address: inner(1, 0),
        },
        ScratchSlot {
            name: "den_1".into(),
            address: inner(1, 1),
        },
    ];
    for k in 1..=vars {
        let (num, den) = (inner(k, 0), inner(k, 1));
        let (flat_num, flat_den) = (
            PolyAddress::Scratch(2 * (k - 1)),
            PolyAddress::Scratch(2 * (k - 1) + 1),
        );
        let cross = |p, q| GateDef::TreeCross { left: p, right: q };
        let product = |q| GateDef::TreeProduct { input: q };
        layers.push(LayerSpec {
            halving: true,
            num_vars: vars - k,
            width: 2,
            cached: vec![],
            producing: vec![
                ProducingEntry {
                    relation: relations.len() as u32,
                    output: inner(k + 1, 0),
                    gate: cross(num, den),
                },
                ProducingEntry {
                    relation: relations.len() as u32 + 1,
                    output: inner(k + 1, 1),
                    gate: product(den),
                },
            ],
            enforcing: vec![],
        });
        relations.push(Relation {
            name: format!("define_num_{}", k + 1),
            output: Some(scratch.len() as u32),
            gate: cross(flat_num, flat_den),
        });
        scratch.push(ScratchSlot {
            name: format!("num_{}", k + 1),
            address: inner(k + 1, 0),
        });
        relations.push(Relation {
            name: format!("define_den_{}", k + 1),
            output: Some(scratch.len() as u32),
            gate: product(flat_den),
        });
        scratch.push(ScratchSlot {
            name: format!("den_{}", k + 1),
            address: inner(k + 1, 1),
        });
    }
    let top = vars + 1;
    CircuitArtifact {
        format_version: FORMAT_VERSION,
        coefficient_encoding: COEFFICIENT_ENCODING_CANONICAL_LE,
        trace_vars: vars,
        memory: vec![],
        witness: vec!["p".into(), "q".into()],
        setup: vec![],
        virtuals: vec![],
        layers,
        relations,
        lookups: vec![],
        scratch,
        outputs: vec![inner(top, 0), inner(top, 1)],
        // The circuit has no enforcing gate, so every row satisfies it.
        padding: Padding {
            row: vec![Fr::ZERO, Fr::ONE],
            zero_row_valid: false,
        },
    }
}

/// `(p, q)` over `2^vars` rows, `q` never 0.
fn fractions(vars: u32, seed: u64) -> (Vec<Fr>, Vec<Fr>) {
    let mut rng = Rng::new(seed);
    let rows = 1usize << vars;
    let p: Vec<Fr> = (0..rows).map(|_| fr(&mut rng)).collect();
    let q: Vec<Fr> = (0..rows).map(|_| fr(&mut rng) + Fr::ONE).collect();
    assert!(q.iter().all(|v| *v != Fr::ZERO));
    (p, q)
}

fn base(p: &[Fr], q: &[Fr]) -> BaseLayer {
    BaseLayer::new(vec![
        (
            PolyAddress::Witness(0),
            MultilinearPoly::new(PolyBacking::Fr(p.to_vec())),
        ),
        (
            PolyAddress::Witness(1),
            MultilinearPoly::new(PolyBacking::Fr(q.to_vec())),
        ),
    ])
}

/// The fraction tree computes `a/b + c/d = (ad + cb)/(bd)` all the way up: its
/// root pair is `(Σ p_y/q_y · Π q_y, Π q_y)`, which is the sum by direct
/// inversion times the denominator product. Held at three heights, and the
/// circuit validates, forwards, self-checks, proves and verifies.
#[test]
fn a_fraction_tree_adds_every_rows_fraction() {
    for vars in [1, 3, 6] {
        let a = fraction_circuit(vars);
        assert_eq!(a.validate(), Ok(()), "{vars} variables");
        let (p, q) = fractions(vars, 0x5115_0001 + vars as u64);
        let base = base(&p, &q);
        let challenges = ExternalChallenges::new();
        let values = forward(&a, &base, &challenges);
        assert_eq!(self_check(&a, &values, &challenges), Ok(()));

        let denominator = q.iter().fold(Fr::ONE, |acc, v| acc * *v);
        let sum = p.iter().zip(&q).fold(Fr::ZERO, |acc, (n, d)| {
            acc + *n * d.inverse().expect("q != 0")
        });
        let top = values.layers.last().expect("a top layer");
        assert_eq!(top[1].get(0), denominator, "{vars}: the den root");
        assert_eq!(top[0].get(0), sum * denominator, "{vars}: the num root");

        assert_eq!(prove_and_verify(&a, &base, &values), Ok(()));
    }
}

/// Acceptance 5's mechanism, on the tree itself. A leaf whose pair is `(0, 0)`
/// annihilates everything: `(x, y) + (0, 0) = (x·0 + 0·y, y·0) = (0, 0)`, so
/// the root is `(0, 0)` whatever every other row holds — an arbitrary,
/// unbalanced set of fractions included. The numerator check alone, which is
/// the test-only fork of the assertion, accepts it; only `den != 0` refuses it.
///
/// The witness is crafted directly here. A prover of the real schedule cannot
/// reach a zero denominator by choosing columns, because `g` is drawn after
/// every column is committed (`docs/spec/lookup.md` §2) — which is why the
/// check costs nothing and is kept anyway: it is the one thing standing between
/// a steerable denominator and a channel that proves nothing at all.
#[test]
fn a_zero_pair_annihilates_the_tree_and_only_the_den_check_refuses_it() {
    let vars = 4;
    let a = fraction_circuit(vars);
    let (p, q) = fractions(vars, 0x5115_0005);
    let challenges = ExternalChallenges::new();

    // Honest: an arbitrary set of fractions does not sum to zero, so the
    // numerator check refuses it on its own.
    let values = forward(&a, &base(&p, &q), &challenges);
    let top = values.layers.last().expect("a top layer");
    let unbalanced = (top[0].get(0), top[1].get(0));
    assert_ne!(unbalanced.0, Fr::ZERO, "an arbitrary sum is not zero");
    assert_ne!(unbalanced.1, Fr::ZERO);
    assert!(!channel_holds(unbalanced));

    // The same rows with row 3's pair zeroed.
    let (mut forged_p, mut forged_q) = (p.clone(), q.clone());
    forged_p[3] = Fr::ZERO;
    forged_q[3] = Fr::ZERO;
    let values = forward(&a, &base(&forged_p, &forged_q), &challenges);
    let top = values.layers.last().expect("a top layer");
    let forged = (top[0].get(0), top[1].get(0));
    assert_eq!(forged, (Fr::ZERO, Fr::ZERO), "a zero pair reaches the root");
    assert_eq!(forged.0, Fr::ZERO, "num == 0 alone accepts it");
    assert!(!channel_holds(forged), "both conditions refuse it");

    // And the GKR proof of it is honest: nothing below the root notices, so the
    // root check is the only place the forgery can be caught.
    assert_eq!(
        self_check(&a, &values, &challenges),
        Ok(()),
        "every gate holds on the forged witness"
    );
    assert_eq!(
        prove_and_verify(&a, &base(&forged_p, &forged_q), &values),
        Ok(())
    );
}

fn prove_and_verify(
    a: &CircuitArtifact,
    base: &BaseLayer,
    values: &gkr::LayerValues,
) -> Result<(), GkrError> {
    let columns: Vec<MultilinearPoly> = a
        .committed()
        .into_iter()
        .map(|address| base.get(address).expect("a column").clone())
        .collect();
    let digest = witness_digest(&columns);
    let bound = || {
        let mut t = Transcript::new();
        absorb_witness_digest(&mut t, digest);
        t
    };
    let challenges = ExternalChallenges::new();
    let proof = prove(a, values, &challenges, &mut bound());
    let top = values.layers.last().expect("a top layer");
    let tables = a
        .outputs
        .iter()
        .map(|out| match *out {
            PolyAddress::Inner { offset, .. } => top[offset as usize].clone(),
            other => panic!("an output is an inner address, not {other}"),
        })
        .collect();
    verify(
        a,
        &proof,
        &OutputClaims { tables },
        &challenges,
        &mut bound(),
    )
    .map(|_| ())
}

// ---------------------------------------------------------------------------
// Acceptance 9: the virtual tables
// ---------------------------------------------------------------------------

/// Acceptance 9. Each range table's closed form is the multilinear extension of
/// its own table: materialize `virtual_at_row` over `2^n` rows, evaluate that
/// polynomial directly at pseudo-random points, and require `virtual_at_point`
/// to agree. Held at `n` below, at and above each bound, so both the
/// "every value once per `2^bits` rows" case and the "the table is the row
/// index" case are covered.
#[test]
fn each_range_tables_closed_form_is_its_multilinear_extension() {
    let mut rng = Rng::new(0x5115_0009);
    for (kind, bits) in [(VirtualKind::Range19, 19), (VirtualKind::Range16, 16)] {
        for n in [2u32, bits - 1, bits, bits + 1] {
            let rows = 1usize << n;
            let table: Vec<Fr> = (0..rows).map(|y| virtual_at_row(kind, y)).collect();
            let poly = MultilinearPoly::new(PolyBacking::Fr(table.clone()));
            for _ in 0..4 {
                let point: Vec<Fr> = (0..n).map(|_| fr(&mut rng)).collect();
                assert_eq!(
                    virtual_at_point(kind, &point),
                    poly.evaluate(&point),
                    "{kind:?} at {n} variables"
                );
            }
            // On the cube it is the low `min(bits, n)` bits of the row index.
            let mask = (1u64 << bits.min(n)) - 1;
            for y in [0usize, 1, rows / 3, rows - 1] {
                assert_eq!(table[y], Fr::from_u64(y as u64 & mask), "{kind:?} row {y}");
            }
        }
    }
}

/// Acceptance 9's negative control: a closed form perturbed in one bit's weight
/// is no longer the table's extension, and the comparison above catches it.
#[test]
fn a_perturbed_closed_form_disagrees_with_the_table() {
    let mut rng = Rng::new(0x5115_000a);
    let (kind, n) = (VirtualKind::Range16, 8u32);
    let rows = 1usize << n;
    let table: Vec<Fr> = (0..rows).map(|y| virtual_at_row(kind, y)).collect();
    let poly = MultilinearPoly::new(PolyBacking::Fr(table));
    // `Σ_{j < bits} 2^j·y_j` with the weight of variable 3 doubled.
    let perturbed = |point: &[Fr]| -> Fr {
        point.iter().enumerate().fold(Fr::ZERO, |acc, (j, y)| {
            let weight = if j == 3 { 1u64 << (j + 1) } else { 1u64 << j };
            acc + Fr::from_u64(weight) * *y
        })
    };
    let mut disagreements = 0;
    for _ in 0..4 {
        let point: Vec<Fr> = (0..n).map(|_| fr(&mut rng)).collect();
        assert_eq!(virtual_at_point(kind, &point), poly.evaluate(&point));
        if perturbed(&point) != poly.evaluate(&point) {
            disagreements += 1;
        }
    }
    assert_eq!(
        disagreements, 4,
        "the perturbed form is caught at every point"
    );
}

// ---------------------------------------------------------------------------
// The derived slots and the root check
// ---------------------------------------------------------------------------

/// `insert_lookup_challenges` fills `g`, `β` and every derived power, and the
/// decoder's neutral slot is `g − Σ_{j < width} β^j` — the denominator of the
/// `MINUS_ONE` tuple a switched-off decoder row looks up. A circuit with no
/// decoder channel gets no neutral slot.
#[test]
fn the_derived_lookup_slots_are_the_powers_and_the_neutral_denominator() {
    let mut rng = Rng::new(0x5115_000b);
    let (g, beta) = (fr(&mut rng), fr(&mut rng));
    for width in 0..=lookup_channel::MAX_TUPLE {
        let mut ch = ExternalChallenges::new();
        insert_lookup_challenges(&mut ch, g, beta, width);
        assert_eq!(ch.get(challenge_slot::LOOKUP_G), Some(g));
        let mut power = beta;
        for slot in challenge_slot::LOOKUP_BETA_POWERS {
            assert_eq!(ch.get(slot), Some(power), "slot {slot}");
            power *= beta;
        }
        let neutral = ch.get(challenge_slot::LOOKUP_DECODER_NEUTRAL);
        match width {
            0 => assert_eq!(neutral, None, "no decoder channel, no neutral slot"),
            _ => {
                let mut sum = Fr::ZERO;
                let mut p = Fr::ONE;
                for _ in 0..width {
                    sum += p;
                    p *= beta;
                }
                assert_eq!(neutral, Some(g - sum), "width {width}");
            }
        }
    }
}

/// The root check is `num == 0 AND den != 0`, and neither half alone.
#[test]
fn a_channel_holds_only_at_a_zero_numerator_over_a_nonzero_denominator() {
    let one = Fr::ONE;
    assert!(channel_holds((Fr::ZERO, one)));
    assert!(!channel_holds((one, one)), "a nonzero numerator");
    assert!(!channel_holds((Fr::ZERO, Fr::ZERO)), "a zero denominator");
    assert!(!channel_holds((one, Fr::ZERO)));
}
