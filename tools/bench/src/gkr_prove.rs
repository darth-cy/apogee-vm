//! S13: the GKR engine's four passes — `forward`, `self_check`, `prove` and
//! `verify` — over one circuit wide enough that per-gate and per-row costs
//! show, at 2^VARS rows.
//!
//! The circuit is written as data, a struct literal followed by `validate`,
//! exactly as the toy is:
//!
//! ```text
//! base      M[0..4]  W[0..24]  (u32)   S[0..4]  (bits)   V[row]        32 columns
//! list 0    C{0}[0] shift = γ·W[0] + row                   (cached)
//!           L{1}[0..32]: 32 producing gates, cycling through Product,
//!                        AffineProduct over the cached entry, MaskIntoIdentity,
//!                        and Quadratic over a challenge, the cached entry and
//!                        a bit column
//!           0 = W[23] − W[22]·S[0]                         (enforcing, Quadratic)
//!           0 = S[1]·S[1] − S[1]                           (enforcing, Quadratic)
//! list 1    L{2}[0..16]: Product, Linear and Quadratic over pairs of L{1}
//! list k    L{k+1}[0..16] = Π L{k}[j], for k = 2..2+VARS    (halving, to one row)
//! outputs   L{2+VARS}[0..16]: the 16 product-tree roots
//! ```
//!
//! The outputs are roots, as a real circuit's are, so absorbing them is 16
//! scalars and every pass's time is the engine's own.
//!
//! Not measured: the base's digest. The prover and verifier each start from an
//! empty transcript and share one fixed challenge value, which is what the
//! passes see after a binding they do not perform themselves.

use std::hint::black_box;
use std::time::Instant;

use constants::challenge_slot;
use constraints::{
    CachedEntry, CircuitArtifact, Coeff, EnforcingEntry, GateDef, LayerSpec, Padding, PolyAddress,
    ProducingEntry, Relation, ScratchSlot, VirtualKind, COEFFICIENT_ENCODING_CANONICAL_LE,
    FORMAT_VERSION,
};
use field::Fr;
use gkr::{
    forward, prove, self_check, verify, BaseLayer, ExternalChallenges, LayerValues, OutputClaims,
};
use poly::{MultilinearPoly, PolyBacking};
use test_support::Rng;
use transcript::Transcript;

use crate::timing::{ms, next_canonical, Best, REPS, SEED};

/// The trace height, in variables.
const VARS: u32 = 18;
/// Committed columns, by kind.
const MEMORY: u32 = 4;
const WITNESS: u32 = 24;
const SETUP: u32 = 4;
/// Producing gates of list 0 and of list 1.
const WIDTH_1: u32 = 32;
const WIDTH_2: u32 = 16;

fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

fn inner(layer: u32, offset: u32) -> PolyAddress {
    PolyAddress::Inner { layer, offset }
}

/// Committed column `i`, modulo the layout, in layout order `M`, `W`, `S`.
fn committed(i: u32) -> PolyAddress {
    let i = i % (MEMORY + WITNESS + SETUP);
    if i < MEMORY {
        PolyAddress::Memory(i)
    } else if i < MEMORY + WITNESS {
        PolyAddress::Witness(i - MEMORY)
    } else {
        PolyAddress::Setup(i - MEMORY - WITNESS)
    }
}

/// List 0's gate `j` and its relation, which spells the cached entry out.
fn list0_gate(j: u32) -> (GateDef, GateDef) {
    let gamma = Coeff::Challenge(challenge_slot::TOY);
    let row = PolyAddress::Virtual(VirtualKind::RowIndex);
    let shift = PolyAddress::Cached {
        layer: 0,
        offset: 0,
    };
    let bit = PolyAddress::Setup(j / 4 % SETUP);
    let x = committed(j);
    match j % 4 {
        0 => {
            let g = GateDef::Product {
                coeff: lit(j as u64 + 1),
                left: x,
                right: committed(j + 5),
            };
            (g.clone(), g)
        }
        1 => {
            let right = vec![(lit(1), committed(j + 7))];
            (
                GateDef::AffineProduct {
                    left: vec![(lit(1), shift), (lit(2), x)],
                    left_constant: lit(0),
                    right: right.clone(),
                    right_constant: lit(1),
                },
                GateDef::AffineProduct {
                    left: vec![(gamma, PolyAddress::Witness(0)), (lit(1), row), (lit(2), x)],
                    left_constant: lit(0),
                    right,
                    right_constant: lit(1),
                },
            )
        }
        2 => {
            let g = GateDef::MaskIntoIdentity {
                input: x,
                mask: bit,
            };
            (g.clone(), g)
        }
        _ => {
            let products = vec![
                (lit(5), committed(j + 1), committed(j + 2)),
                (Coeff::Literal(-Fr::ONE), committed(j + 3), bit),
            ];
            (
                GateDef::Quadratic {
                    constant: lit(7),
                    linear: vec![(gamma, x), (lit(1), shift)],
                    products: products.clone(),
                },
                GateDef::Quadratic {
                    constant: lit(7),
                    linear: vec![(gamma, x), (gamma, PolyAddress::Witness(0)), (lit(1), row)],
                    products,
                },
            )
        }
    }
}

/// List 1's gate `j` over two columns `left` and `right`.
fn list1_gate(j: u32, left: PolyAddress, right: PolyAddress) -> GateDef {
    match j % 4 {
        0 | 2 => GateDef::Product {
            coeff: lit(1),
            left,
            right,
        },
        1 => GateDef::Linear {
            terms: vec![(lit(1), left), (lit(3), right)],
            constant: lit(1),
        },
        _ => GateDef::Quadratic {
            constant: lit(1),
            linear: vec![(Coeff::Challenge(challenge_slot::TOY), left)],
            products: vec![(lit(1), right, right)],
        },
    }
}

fn names(prefix: &str, n: u32) -> Vec<String> {
    (0..n).map(|i| format!("{prefix}{i}")).collect()
}

/// The circuit at `vars` variables, validated.
fn circuit(vars: u32) -> CircuitArtifact {
    let gated_copy = GateDef::Quadratic {
        constant: lit(0),
        linear: vec![(lit(1), PolyAddress::Witness(23))],
        products: vec![(
            Coeff::Literal(-Fr::ONE),
            PolyAddress::Witness(22),
            PolyAddress::Setup(0),
        )],
    };
    let is_bit = GateDef::Quadratic {
        constant: lit(0),
        linear: vec![(Coeff::Literal(-Fr::ONE), PolyAddress::Setup(1))],
        products: vec![(lit(1), PolyAddress::Setup(1), PolyAddress::Setup(1))],
    };

    let mut relations: Vec<Relation> = Vec::new();
    let mut scratch: Vec<ScratchSlot> = Vec::new();

    let mut producing0 = Vec::new();
    for j in 0..WIDTH_1 {
        let (gate, spelled) = list0_gate(j);
        producing0.push(ProducingEntry {
            relation: relations.len() as u32,
            output: inner(1, j),
            gate,
        });
        relations.push(Relation {
            name: format!("define_l1_{j}"),
            output: Some(scratch.len() as u32),
            gate: spelled,
        });
        scratch.push(ScratchSlot {
            name: format!("l1_{j}"),
            address: inner(1, j),
        });
    }
    let mut enforcing0 = Vec::new();
    for (name, gate) in [("gated_copy", gated_copy), ("s1_is_bit", is_bit)] {
        enforcing0.push(EnforcingEntry {
            relation: relations.len() as u32,
            gate: gate.clone(),
        });
        relations.push(Relation {
            name: name.into(),
            output: None,
            gate,
        });
    }

    let mut producing1 = Vec::new();
    for j in 0..WIDTH_2 {
        producing1.push(ProducingEntry {
            relation: relations.len() as u32,
            output: inner(2, j),
            gate: list1_gate(j, inner(1, 2 * j), inner(1, 2 * j + 1)),
        });
        relations.push(Relation {
            name: format!("define_l2_{j}"),
            output: Some(scratch.len() as u32),
            gate: list1_gate(
                j,
                PolyAddress::Scratch(2 * j),
                PolyAddress::Scratch(2 * j + 1),
            ),
        });
        scratch.push(ScratchSlot {
            name: format!("l2_{j}"),
            address: inner(2, j),
        });
    }

    // One halving list per variable: list 2 + h reads layer 2 + h, whose
    // columns are the last WIDTH_2 scratch slots, and halves every one.
    let mut halving = Vec::new();
    for h in 0..vars {
        let (reads, writes) = (2 + h, 3 + h);
        let first = scratch.len() as u32 - WIDTH_2;
        let mut producing = Vec::new();
        for j in 0..WIDTH_2 {
            producing.push(ProducingEntry {
                relation: relations.len() as u32,
                output: inner(writes, j),
                gate: GateDef::TreeProduct {
                    input: inner(reads, j),
                },
            });
            relations.push(Relation {
                name: format!("define_l{writes}_{j}"),
                output: Some(scratch.len() as u32),
                gate: GateDef::TreeProduct {
                    input: PolyAddress::Scratch(first + j),
                },
            });
            scratch.push(ScratchSlot {
                name: format!("l{writes}_{j}"),
                address: inner(writes, j),
            });
        }
        halving.push(LayerSpec {
            halving: true,
            num_vars: vars - 1 - h,
            width: WIDTH_2,
            cached: vec![],
            producing,
            enforcing: vec![],
        });
    }

    let mut layers = vec![
        LayerSpec {
            halving: false,
            num_vars: vars,
            width: WIDTH_1,
            cached: vec![CachedEntry {
                name: "shift".into(),
                address: PolyAddress::Cached {
                    layer: 0,
                    offset: 0,
                },
                gate: GateDef::Linear {
                    terms: vec![
                        (
                            Coeff::Challenge(challenge_slot::TOY),
                            PolyAddress::Witness(0),
                        ),
                        (lit(1), PolyAddress::Virtual(VirtualKind::RowIndex)),
                    ],
                    constant: lit(0),
                },
            }],
            producing: producing0,
            enforcing: enforcing0,
        },
        LayerSpec {
            halving: false,
            num_vars: vars,
            width: WIDTH_2,
            cached: vec![],
            producing: producing1,
            enforcing: vec![],
        },
    ];
    layers.extend(halving);

    let artifact = CircuitArtifact {
        format_version: FORMAT_VERSION,
        coefficient_encoding: COEFFICIENT_ENCODING_CANONICAL_LE,
        trace_vars: vars,
        memory: names("m", MEMORY),
        witness: names("w", WITNESS),
        setup: names("s", SETUP),
        virtuals: vec![(VirtualKind::RowIndex, "row".into())],
        layers,
        relations,
        lookups: vec![],
        scratch,
        outputs: (0..WIDTH_2).map(|j| inner(2 + vars, j)).collect(),
        // The all-zero row satisfies both enforcing gates.
        padding: Padding {
            row: vec![Fr::ZERO; (MEMORY + WITNESS + SETUP) as usize],
            zero_row_valid: true,
        },
    };
    if let Err(e) = artifact.validate() {
        panic!("the gkr-prove circuit is not a circuit: {e}");
    }
    artifact
}

/// A satisfying base: `u32` columns at random, bit columns at random, and
/// `W[23] = W[22]` where `S[0] = 1`, zero elsewhere.
fn base(vars: u32, rng: &mut Rng) -> BaseLayer {
    let rows = 1usize << vars;
    let mut words = |n: u32| -> Vec<Vec<u32>> {
        (0..n)
            .map(|_| (0..rows).map(|_| rng.next_u64() as u32).collect())
            .collect()
    };
    let memory = words(MEMORY);
    let mut witness = words(WITNESS);
    let bits: Vec<Vec<u64>> = (0..SETUP)
        .map(|_| {
            let mut limbs: Vec<u64> = (0..rows.div_ceil(64)).map(|_| rng.next_u64()).collect();
            if rows < 64 {
                limbs[0] &= (1u64 << rows) - 1;
            }
            limbs
        })
        .collect();
    for y in 0..rows {
        let s0 = (bits[0][y / 64] >> (y % 64)) & 1;
        witness[23][y] = if s0 == 1 { witness[22][y] } else { 0 };
    }
    let mut columns = Vec::new();
    for (i, v) in memory.into_iter().enumerate() {
        columns.push((PolyAddress::Memory(i as u32), PolyBacking::U32(v)));
    }
    for (i, v) in witness.into_iter().enumerate() {
        columns.push((PolyAddress::Witness(i as u32), PolyBacking::U32(v)));
    }
    for (i, limbs) in bits.into_iter().enumerate() {
        columns.push((PolyAddress::Setup(i as u32), PolyBacking::U1(limbs, rows)));
    }
    BaseLayer::new(
        columns
            .into_iter()
            .map(|(a, b)| (a, MultilinearPoly::new(b)))
            .collect(),
    )
}

/// The bytes a table occupies, by width.
fn table_bytes(column: &MultilinearPoly) -> usize {
    match column.backing() {
        PolyBacking::U1(limbs, _) => 8 * limbs.len(),
        PolyBacking::U8(v) => v.len(),
        PolyBacking::U16(v) => 2 * v.len(),
        PolyBacking::U32(v) => 4 * v.len(),
        PolyBacking::Fr(v) => 32 * v.len(),
    }
}

fn mib(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

pub fn run() {
    let mut rng = Rng::new(SEED ^ 0x5313_9000);
    let artifact = circuit(VARS);
    let base = base(VARS, &mut rng);
    let mut challenges = ExternalChallenges::new();
    challenges.insert(
        challenge_slot::TOY,
        Fr::from_bytes(&next_canonical(&mut rng)).unwrap(),
    );

    let mut best = Best::new();
    let mut values: Option<LayerValues> = None;
    for _ in 0..REPS {
        drop(values.take());
        let start = Instant::now();
        let v = forward(&artifact, &base, &challenges);
        best.record(start.elapsed());
        values = Some(v);
    }
    let forward_time = best.get();
    let values = values.expect("REPS is at least one");

    let mut best = Best::new();
    for _ in 0..REPS {
        let start = Instant::now();
        let result = self_check(&artifact, &values, &challenges);
        best.record(start.elapsed());
        result.expect("the base satisfies every gate");
    }
    let self_check_time = best.get();

    let mut best = Best::new();
    let mut proof = None;
    for _ in 0..REPS {
        drop(proof.take());
        let mut t = Transcript::new();
        let start = Instant::now();
        let p = prove(&artifact, &values, &challenges, &mut t);
        best.record(start.elapsed());
        proof = Some(p);
    }
    let prove_time = best.get();
    let proof = proof.expect("REPS is at least one");

    let top = values.layers.last().expect("a circuit has a top layer");
    let outputs = OutputClaims {
        tables: artifact
            .outputs
            .iter()
            .map(|out| match *out {
                PolyAddress::Inner { offset, .. } => top[offset as usize].clone(),
                other => panic!("an output is an inner address, not {other}"),
            })
            .collect(),
    };
    let mut best = Best::new();
    for _ in 0..REPS {
        let mut t = Transcript::new();
        let start = Instant::now();
        let result = verify(&artifact, &proof, &outputs, &challenges, &mut t);
        best.record(start.elapsed());
        black_box(result.expect("an honest proof verifies"));
    }
    let verify_time = best.get();

    let base_bytes: usize = artifact
        .committed()
        .iter()
        .map(|a| table_bytes(base.get(*a).expect("a committed column")))
        .sum();
    let layer_bytes: usize = values.layers.iter().flatten().map(table_bytes).sum();
    let gates: usize = artifact
        .layers
        .iter()
        .map(|l| l.cached.len() + l.producing.len() + l.enforcing.len())
        .sum();

    println!(
        "gkr: {} committed columns, {gates} gates over {} lists, n = {VARS} ({} rows), best of {REPS}",
        artifact.committed().len(),
        artifact.depth(),
        1usize << VARS
    );
    println!(
        "  forward                               {:>10.1} ms",
        ms(forward_time)
    );
    println!(
        "  self_check                            {:>10.1} ms",
        ms(self_check_time)
    );
    println!(
        "  prove                                 {:>10.1} ms",
        ms(prove_time)
    );
    println!(
        "  verify                                {:>10.1} ms",
        ms(verify_time)
    );
    println!(
        "  base tables (computed)                {:>10.1} MiB",
        mib(base_bytes)
    );
    println!(
        "  forward's layer tables (computed)     {:>10.1} MiB",
        mib(layer_bytes)
    );
    println!("  not timed: the base digest; both sides start from an empty transcript");
}
